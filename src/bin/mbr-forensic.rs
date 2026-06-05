//! `mbr-forensic` — analyse the Master Boot Record of a disk image.
//!
//! Usage:
//!   mbr-forensic <image>          # human-readable report
//!   mbr-forensic --json <image>   # JSON (requires the `serde` feature)
//!
//! The image is any file exposing the raw bytes of a disk (a `dd`/`.raw` dump,
//! or a decoded container). Only the first sectors are read.

use std::fs::File;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<String> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("usage: mbr-forensic [--json] <image>");
                return ExitCode::from(2);
            }
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: mbr-forensic [--json] <image>");
        return ExitCode::from(2);
    };

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("mbr-forensic: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let analysis = match mbr_forensic::analyse(&mut file, size) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mbr-forensic: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
            match serde_json::to_string_pretty(&analysis) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("mbr-forensic: JSON error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "serde"))]
        {
            eprintln!("mbr-forensic: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        print!("{}", mbr_forensic::report::text_report(&analysis));
    }

    // Exit code reflects the worst finding: 0 clean, 1 if any anomaly present.
    if analysis.anomalies.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
