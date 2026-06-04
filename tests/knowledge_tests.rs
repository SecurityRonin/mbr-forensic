//! TypeCode names sourced from the forensicnomicon knowledge base, including
//! codes beyond the original hardcoded table.
use mbr_forensic::partition::TypeCode;

#[test]
fn expanded_codes_resolve_via_knowledge_base() {
    assert_eq!(TypeCode(0x0A).name(), "OS/2 Boot Manager");
    assert_eq!(TypeCode(0x39).name(), "Plan 9");
}

#[test]
fn original_names_preserved() {
    assert_eq!(TypeCode(0x83).name(), "Linux");
    assert_eq!(TypeCode(0x07).name(), "NTFS / exFAT / IFS");
    assert_eq!(TypeCode(0xCC).name(), "Unknown");
}
