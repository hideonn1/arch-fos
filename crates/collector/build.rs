use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/arch_fos_net.bpf.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_obj = out_dir.join("arch_fos_net.bpf.o");

    let clang_status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-c",
            "bpf/arch_fos_net.bpf.c",
            "-o",
        ])
        .arg(&out_obj)
        .status();

    match clang_status {
        Ok(status) if status.success() => {}
        Ok(status) => {
            panic!("clang failed compiling bpf/arch_fos_net.bpf.c with status {status}");
        }
        Err(err) => {
            panic!("clang is required to build arch-fos-collector eBPF object: {err}");
        }
    }
}
