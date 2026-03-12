use std::fs;
use std::path::PathBuf;

fn main() {
    let mut out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let Some(path) = args.next() else {
                    eprintln!("missing value for --out");
                    std::process::exit(2);
                };
                out = Some(PathBuf::from(path));
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: cargo run -p tarsier-proof-kernel --bin kernel-semantics-export -- \
                     [--out <path>]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let artifact = tarsier_proof_kernel::kernel_semantics_artifact_v1();
    let json = match serde_json::to_string_pretty(&artifact) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("failed to serialize kernel semantics artifact: {err}");
            std::process::exit(1);
        }
    };

    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(err) = fs::create_dir_all(parent) {
                    eprintln!(
                        "failed to create output directory {}: {err}",
                        parent.display()
                    );
                    std::process::exit(1);
                }
            }
        }
        if let Err(err) = fs::write(&path, format!("{json}\n")) {
            eprintln!("failed to write output file {}: {err}", path.display());
            std::process::exit(1);
        }
        eprintln!("wrote {}", path.display());
    } else {
        println!("{json}");
    }
}
