use std::collections::HashSet;

use arch_fos_common::RagSource;
use sqlx::SqlitePool;

#[derive(sqlx::FromRow)]
struct WikiChunkRow {
    title: String,
    url: String,
    section: String,
    content: String,
    embedding: Option<Vec<u8>>,
}

/// Curated offline Arch Wiki security knowledge fallback when `wiki_chunks` is not yet indexed
/// from `arch-wiki-docs` (US-27). Every entry cites an official Arch Wiki page.
const BUILTIN_ARCH_WIKI_CORPUS: &[(&str, &str, &str, &str)] = &[
    (
        "Arch User Repository",
        "https://wiki.archlinux.org/title/Arch_User_Repository",
        "Installing and upgrading packages",
        "AUR packages are user-produced content. Always carefully inspect the PKGBUILD and any .install files before building or installing. Verify source URLs, checksums (avoid SKIP unless justified for VCS sources), maintainer history, and build commands running inside prepare(), build(), and package().",
    ),
    (
        "Security",
        "https://wiki.archlinux.org/title/Security",
        "Hardening and persistence auditing",
        "Audit persistence mechanisms regularly including systemd units and timers, crontabs, shell initialization files (.bashrc, .zshrc), XDG autostart entries, /etc/ld.so.preload, loaded kernel modules, and SUID/SGID binaries. Keep services minimal and disable unused daemons.",
    ),
    (
        "Pacman",
        "https://wiki.archlinux.org/title/Pacman",
        "Querying and verifying package integrity",
        "Use pacman -Qkk to verify installed package files against their local mtree checksums. Configuration files listed in the package backup array are expected to change, while unexpected modifications to binaries under /usr/bin or /usr/lib indicate tampering or corruption. Use pacman -Qo /path to identify the owning package.",
    ),
    (
        "Arch Linux Security Tracker",
        "https://wiki.archlinux.org/title/Security#Arch_Security_Team",
        "Vulnerability tracking and upgrades",
        "Monitor security.archlinux.org for CVEs affecting official repository packages. Always perform full system upgrades with pacman -Syu rather than partial upgrades, and reboot after kernel or core library updates such as glibc or openssl.",
    ),
    (
        "systemd",
        "https://wiki.archlinux.org/title/Systemd",
        "Sandboxing and analyzing services",
        "Inspect active services with systemctl list-units --type=service and review service exposure with systemd-analyze security. Disable unnecessary enabled services with systemctl disable --now <unit>. Apply NoNewPrivileges, ProtectSystem=strict, DynamicUser, and minimal AmbientCapabilities.",
    ),
    (
        "Capabilities",
        "https://wiki.archlinux.org/title/Capabilities",
        "Least privilege and SUID reduction",
        "Linux capabilities split root privileges into fine-grained units such as CAP_BPF, CAP_NET_RAW, and CAP_PERFMON. Prefer file or systemd capabilities over SUID root binaries, and audit unowned SUID/SGID executables.",
    ),
    (
        "Network configuration and firewalls",
        "https://wiki.archlinux.org/title/Simple_stateful_firewall",
        "Listening sockets and outbound filtering",
        "Audit open ports with ss -tulpn and bind local-only services to 127.0.0.1 or Unix sockets rather than 0.0.0.0 or ::. Use nftables or ufw to restrict unexpected inbound connections and investigate unusual outbound ports, high-entropy DNS queries, or periodic C2 beaconing.",
    ),
    (
        "Makepkg",
        "https://wiki.archlinux.org/title/Makepkg",
        "Clean chroot and sandboxed builds",
        "Build untrusted PKGBUILDs in isolated environments such as bubblewrap (bwrap --unshare-net), systemd-nspawn, or clean chroots (extra-x86_64-build) so build scripts cannot access host credentials or exfiltrate data during compilation.",
    ),
];

/// Searches the offline Arch Wiki index in SQLite (`wiki_chunks`) using hybrid vector cosine
/// similarity (when embeddings are present) + lexical token overlap, falling back to the
/// built-in Arch Wiki security corpus when `wiki_chunks` is empty (US-27).
pub async fn search_arch_wiki(
    pool: &SqlitePool,
    query_text: &str,
    query_embedding: Option<&[f32]>,
    limit: usize,
) -> Result<Vec<RagSource>, sqlx::Error> {
    let rows: Vec<WikiChunkRow> = sqlx::query_as(
        "SELECT title, url, section, content, embedding FROM wiki_chunks LIMIT 5000",
    )
    .fetch_all(pool)
    .await?;

    let query_tokens = tokenize(query_text);
    let mut scored: Vec<RagSource> = Vec::new();

    if rows.is_empty() {
        for &(title, url, section, content) in BUILTIN_ARCH_WIKI_CORPUS {
            let doc_tokens = tokenize(&format!("{title} {section} {content}"));
            let score = lexical_score(&query_tokens, &doc_tokens);
            if score > 0.0 {
                scored.push(RagSource {
                    title: title.to_string(),
                    url: url.to_string(),
                    section: section.to_string(),
                    snippet: truncate_snippet(content, 280),
                    score,
                });
            }
        }
    } else {
        for row in rows {
            let vec_score = match (query_embedding, row.embedding.as_deref()) {
                (Some(q_emb), Some(blob)) => {
                    let doc_emb = unpack_f32_le(blob);
                    cosine_similarity(q_emb, &doc_emb)
                }
                _ => 0.0,
            };
            let doc_tokens = tokenize(&format!("{} {} {}", row.title, row.section, row.content));
            let lex_score = lexical_score(&query_tokens, &doc_tokens);

            let combined = if vec_score > 0.0 {
                0.7 * vec_score + 0.3 * lex_score
            } else {
                lex_score
            };

            if combined > 0.0 {
                scored.push(RagSource {
                    title: row.title,
                    url: row.url,
                    section: row.section,
                    snippet: truncate_snippet(&row.content, 280),
                    score: combined,
                });
            }
        }
    }

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scored.truncate(limit.clamp(1, 10));
    Ok(scored)
}

/// Packs an `f32` embedding slice into little-endian bytes for SQLite `BLOB` storage.
#[must_use]
pub fn pack_f32_le(vec: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vec.len() * 4);
    for &v in vec {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Unpacks little-endian bytes from SQLite `BLOB` into an `f32` embedding vector.
#[must_use]
pub fn unpack_f32_le(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

/// Computes cosine similarity in `[0.0, 1.0]` (clamped for non-negative ranking).
#[must_use]
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = f64::from(x);
        let yf = f64::from(y);
        dot += xf * yf;
        norm_a += xf * xf;
        norm_b += yf * yf;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (dot / denom).max(0.0)
    }
}

fn tokenize(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.len() >= 3)
        .collect()
}

fn lexical_score(query: &HashSet<String>, doc: &HashSet<String>) -> f64 {
    if query.is_empty() || doc.is_empty() {
        return 0.0;
    }
    let matches = query.iter().filter(|t| doc.contains(*t)).count();
    (matches as f64) / (query.len() as f64)
}

fn truncate_snippet(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let s: String = trimmed.chars().take(max_chars).collect();
        format!("{s}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_embedding_pack_unpack_and_cosine_work() {
        let v1 = vec![1.0_f32, 0.0, 0.5];
        let v2 = vec![1.0_f32, 0.0, 0.5];
        let packed = pack_f32_le(&v1);
        let unpacked = unpack_f32_le(&packed);
        assert_eq!(unpacked, v1);
        assert!((cosine_similarity(&unpacked, &v2) - 1.0).abs() < 1e-6);
    }
}
