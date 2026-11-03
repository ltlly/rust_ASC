mod dex_fixture;
mod zip_fixture;

use dex_fixture::{get_u32, make_class_only_dex, make_dex041_container};
use rust_ASC::asc_client::apk_handler::{ApkHandler, DexSourceUnit};
use tempfile::tempdir;
use zip_fixture::{CompressionMethod, write_apk};

#[test]
fn exact_unit_selects_raw_archived_and_nested_bytes_without_name_discovery() {
    let dir = tempdir().unwrap();
    let first = make_class_only_dex(&["Lalpha/First;"], 0, b"035");
    let second = make_class_only_dex(&["Lbeta/Second;"], 0, b"035");
    let file = dir.path().join("input");
    for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        let inner = dir.path().join("inner.apk");
        write_apk(
            &inner,
            &[("classes.dex", &first), ("base/dex/payload.bin", &second)],
            compression,
        );
        let inner_bytes = std::fs::read(&inner).unwrap();
        for entries in [
            vec![],
            vec!["base/dex/payload.bin"],
            vec!["split.apk", "base/dex/payload.bin"],
        ] {
            match entries.len() {
                0 => std::fs::write(&file, &second).unwrap(),
                1 => std::fs::write(&file, &inner_bytes).unwrap(),
                _ => write_apk(&file, &[("split.apk", &inner_bytes)], compression),
            }
            for threads in [1, 2] {
                let unit = DexSourceUnit {
                    entries: entries.iter().map(|s| s.to_string()).collect(),
                    offset: 0,
                };
                let rows = ApkHandler::new(file.to_str().unwrap(), false, threads)
                    .try_get_class_outputs_in_unit(
                        &unit,
                        &["Lbeta/Second;".into(), "Lalpha/First;".into()],
                        true,
                        None,
                        None,
                    )
                    .unwrap();
                let output = &rows[0].1.as_ref().unwrap().1;
                assert!(output.source.contains("class Second"), "{}", output.source);
                assert!(output.input_revision.is_some());
                assert!(!output.member_references.is_empty());
                assert!(
                    rows[1].1.is_none(),
                    "must not search another DEX for a missing class"
                );
            }
        }
    }
}

#[test]
fn dex041_exact_header_preserves_absolute_container_offsets() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("container.dex");
    let data = make_dex041_container();
    let offset = get_u32(&data, 0x20) as usize;
    std::fs::write(&file, &data).unwrap();
    let handler = ApkHandler::new(file.to_str().unwrap(), false, 2);
    for (offset, class, absent) in [
        (0, "Lalpha/First;", "Lbeta/Second;"),
        (offset, "Lbeta/Second;", "Lalpha/First;"),
    ] {
        let rows = handler
            .try_get_class_outputs_in_unit(
                &DexSourceUnit {
                    entries: vec![],
                    offset,
                },
                &[class.into(), absent.into()],
                true,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            rows[0].1.as_ref().unwrap().1.member_references[0]
                .class
                .as_str(),
            class
        );
        assert!(rows[1].1.is_none());
    }
    assert!(
        handler
            .try_get_class_outputs_in_unit(
                &DexSourceUnit {
                    entries: vec![],
                    offset: offset + 1
                },
                &["Lbeta/Second;".into()],
                true,
                None,
                None
            )
            .is_err()
    );
}

#[test]
fn exact_archive_selection_rejects_ambiguous_missing_and_truncated_entries() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("bad.zip");
    let dex = make_class_only_dex(&["LTest;"], 0, b"035");
    for entries in [
        vec![("same.dex", dex.as_slice()), ("same.dex", dex.as_slice())],
        vec![("other.dex", dex.as_slice())],
        vec![("same.dex", b"bad".as_slice())],
    ] {
        write_apk(&file, &entries, CompressionMethod::Stored);
        assert!(
            ApkHandler::new(file.to_str().unwrap(), false, 1)
                .try_get_class_outputs_in_unit(
                    &DexSourceUnit {
                        entries: vec!["same.dex".into()],
                        offset: 0
                    },
                    &["LTest;".into()],
                    true,
                    None,
                    None
                )
                .is_err()
        );
    }
    std::fs::write(&file, b"PK\x03\x04").unwrap();
    assert!(
        ApkHandler::new(file.to_str().unwrap(), false, 1)
            .try_get_class_outputs_in_unit(
                &DexSourceUnit {
                    entries: vec!["same.dex".into()],
                    offset: 0
                },
                &["LTest;".into()],
                true,
                None,
                None
            )
            .is_err()
    );
}
