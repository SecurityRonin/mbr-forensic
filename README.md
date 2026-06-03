# mbr-forensic

[![Crates.io](https://img.shields.io/crates/v/mbr-forensic.svg)](https://crates.io/crates/mbr-forensic)
[![docs.rs](https://img.shields.io/docsrs/mbr-forensic)](https://docs.rs/mbr-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/mbr-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/mbr-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Forensic-grade Master Boot Record (MBR) parser for Rust. Goes beyond partition enumeration to surface structural anomalies, slack-space content, anti-forensic indicators, and cross-field inconsistencies that every other MBR crate silently ignores.

## Rust library

```toml
[dependencies]
mbr-forensic = "0.1"
```

## Quick start

```rust
use mbr_forensic::{parse_mbr_sector, analyse};
use std::fs::File;

// Pure parsing from a 512-byte buffer — no I/O, no panics:
let mut f = File::open("disk.img")?;
let analysis = analyse(&mut f, disk_size_bytes)?;

for anomaly in &analysis.anomalies {
    println!("[{:?}] offset {:#x}  {}", anomaly.severity, anomaly.offset, anomaly.note);
}
# Ok::<(), mbr_forensic::Error>(())
```

## What makes this different from every other MBR crate

Most MBR crates answer one question: "what partitions are on this disk?" `mbr-forensic` answers the questions a digital forensics examiner actually needs:

| Feature | Other MBR crates | mbr-forensic |
|---|---|---|
| Partition enumeration | ✅ | ✅ |
| Boot code identification (GRUB 2, Windows, Syslinux …) | ✗ | ✅ |
| Wiped / erased boot code detection | ✗ | ✅ |
| Residual (deleted) partition entries | ✗ | ✅ |
| Declared type vs detected filesystem mismatch | ✗ | ✅ |
| Unpartitioned gap analysis (pre / between / post) | ✗ | ✅ |
| Extended partition EBR chain traversal | partial | ✅ full |
| EBR slack-byte inspection | ✗ | ✅ |
| EBR cycle / excessive-depth detection | ✗ | ✅ |
| NT disk serial (offset 440) | ✗ | ✅ |
| Reserved byte audit (offset 444–445) | ✗ | ✅ |
| CHS ↔ LBA cross-validation | ✗ | ✅ |
| Shannon entropy on slack regions | ✗ | ✅ |
| Adversarial-input hardening + fuzz testing | ✗ | ✅ |

## Anomaly types

Every detected condition is returned as an `Anomaly { severity, kind, offset, note }`:

```
NonZeroReserved          bytes 444–445 non-zero
MultipleBootable         > 1 partition has 0x80 status
NoBootablePartition      active partitions but none marked bootable
ResidualEntry            type=0x00 but non-zero LBA fields → deleted partition
OverlappingPartitions    LBA range intersection between two entries
OutOfBounds              partition end exceeds reported disk size
ChsLbaInconsistency      CHS-encoded values disagree with LBA
EbrCycle                 EBR next-pointer forms a loop
EbrExcessiveDepth        EBR chain exceeds 64 levels
EbrSlackData             EBR entries 2–3 contain non-zero bytes
PrePartitionSpace        sectors before the first partition
InterPartitionGap        unpartitioned space between partitions
PostPartitionSpace       trailing space after the last partition
SignatureMismatch        declared type ≠ detected filesystem magic
WipedBootCode            boot code is all zeros
ErasedBootCode           boot code is all 0xFF
UnknownBootCode          boot code matches no known signature
HighEntropySlack         high-entropy bytes in a slack region
```

## Filesystem fingerprinting

`mbr-forensic` reads the first sector of each partition and matches it against known magic bytes, independently of the declared partition type. A mismatch between the declared type and the detected filesystem is surfaced as a `SignatureMismatch` anomaly.

Detected filesystem types: `Ext` (ext2/3/4), `Ntfs`, `Fat`, `ExFat`, `Apfs`, `Xfs`, `LinuxSwap`, `LinuxLvm`, `Luks`, `AllZeros`, `Unknown`.

## Boot code identification

The first 446 bytes of the MBR are matched against signatures for known bootloaders:

| `BootCodeId` | Description |
|---|---|
| `Windows7Plus` | Windows 7 / Server 2008 R2 and later |
| `WindowsVista` | Windows Vista / Server 2008 |
| `Grub2` | GRUB 2 boot.img |
| `GrubLegacy` | GRUB Legacy stage1 |
| `Syslinux` | Syslinux / EXTLINUX |
| `AllZeros` | Wiped — all zeros |
| `AllOnes` | Erased — all 0xFF |
| `Unknown` | No known signature matched |

## API

### Parse a raw 512-byte MBR sector (pure, no I/O)

```rust
use mbr_forensic::parse_mbr_sector;

let sector = std::fs::read("disk.img")?;
let mbr = parse_mbr_sector(&sector[..512])?;

println!("Disk serial: {:#010X}", mbr.disk_serial);
for (i, entry) in mbr.entries.iter().enumerate() {
    if !entry.is_empty() {
        println!("  [{i}] type={} lba={} count={}", entry.type_code.name(), entry.lba_start, entry.lba_count);
    }
}
# Ok::<(), mbr_forensic::Error>(())
```

### Full forensic analysis from any `Read + Seek`

```rust
use mbr_forensic::analyse;
use std::fs::File;

let mut f = File::open("disk.img")?;
let meta = f.metadata()?;
let analysis = analyse(&mut f, meta.len())?;

println!("Boot code: {:?}", analysis.boot_code_id);
println!("Partitions: {}", analysis.partitions.len());
println!("Gaps: {}", analysis.gaps.len());
println!("Anomalies: {}", analysis.anomalies.len());

for a in analysis.anomalies.iter().filter(|a| a.severity >= mbr_forensic::Severity::Medium) {
    println!("  [{:?}] {}", a.severity, a.note);
}
# Ok::<(), mbr_forensic::Error>(())
```

### Entropy analysis on slack regions

```rust
use mbr_forensic::entropy;

let slack = &sector[446..512]; // example: partition table area
let e = entropy::shannon(slack);
if e > 6.0 {
    println!("High-entropy slack ({e:.2} bits/byte) — possible hidden data");
}
```

## Security

`mbr-forensic` is designed for use on untrusted disk images from potentially compromised systems:

- **No panics on malicious input** — all arithmetic uses checked or saturating operations; fuzz-tested with `cargo fuzz`
- **EBR cycle detection** — visited-LBA set prevents infinite loops
- **Overflow-safe EBR chain** — `checked_add` terminates the chain on arithmetic overflow
- **Depth cap** — EBR chains exceeding 64 levels are flagged and stopped
- **Truncation-safe** — read errors on truncated images terminate traversal gracefully rather than propagating

### Running the fuzz targets

```bash
# Requires nightly Rust and cargo-fuzz
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run parse_mbr_sector
cargo +nightly fuzz run analyse_full
```

## Testing

103 tests (unit + integration) with 100% line coverage across all modules. Every public API, every error path, and every anomaly type is exercised.

```bash
cargo test
```

For coverage:

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --all-features
```

## Related

**mbr-forensic** analyses the partition layout. To read the actual filesystem data that lives inside each partition, these crates provide `Read + Seek` over common disk container formats:

| Crate | Format |
|---|---|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / Expert Witness Format (EnCase, FTK Imager) |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK sparse/monolithic |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX (Hyper-V, Azure) |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD (Virtual PC / Hyper-V Gen-1) |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QEMU / KVM QCOW2 |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / dd images |

For forensic integrity analysis of container formats:

| Crate | Format |
|---|---|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 structural audit, Adler-32 repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX integrity analysis |
| [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) | GPT forensic analysis (backup header, CRC32, phantom entries) |

## License

MIT

---

[Privacy Policy](https://securityronin.github.io/mbr-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/mbr-forensic/terms/) · © 2026 Security Ronin Ltd
