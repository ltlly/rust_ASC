// Auth: MG1937

pub use radguard::writer::{MemberKind, MemberReference};

/// Decompile a target class from an in-memory DEX using RadGuard.
pub fn decompile_dex_bytes(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    radguard::decompile_dex_bytes(dex_bytes, dalvik_class_fmt)
        .map(|output| output.source)
        .unwrap_or_else(|error| format!("/* RadGuard decompiler error: {error} */\n"))
}

pub fn decompile_dex_bytes_with_metadata(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
) -> (String, Vec<MemberReference>) {
    decompile_dex_bytes_with_metadata_mode(dex_bytes, dalvik_class_fmt, false)
}

pub fn decompile_dex_bytes_with_metadata_mode(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
    semantic_metadata: bool,
) -> (String, Vec<MemberReference>) {
    let output = decompile_dex_output(dex_bytes, dalvik_class_fmt, semantic_metadata, None);
    (output.source, output.member_references)
}

pub fn decompile_dex_output(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
    semantic_metadata: bool,
    names: Option<std::sync::Arc<Vec<radguard::writer::VariableNames>>>,
) -> radguard::writer::SourceOutput {
    decompile_dex_output_with_symbols(dex_bytes, dalvik_class_fmt, semantic_metadata, names, None)
}

pub fn decompile_dex_output_with_symbols(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
    semantic_metadata: bool,
    names: Option<std::sync::Arc<Vec<radguard::writer::VariableNames>>>,
    symbols: Option<std::sync::Arc<radguard::writer::SymbolNames>>,
) -> radguard::writer::SourceOutput {
    decompile_dex_output_with_options(dex_bytes, dalvik_class_fmt, semantic_metadata, names, symbols, None)
}

pub fn decompile_dex_output_with_options(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
    semantic_metadata: bool,
    names: Option<std::sync::Arc<Vec<radguard::writer::VariableNames>>>,
    symbols: Option<std::sync::Arc<radguard::writer::SymbolNames>>,
    options: Option<radguard::writer::RenderOptions>,
) -> radguard::writer::SourceOutput {
    radguard::Decompiler::parse(dex_bytes)
        .and_then(|d| {
            d.with_semantic_metadata(semantic_metadata)
                .with_variable_names(names)
                .with_symbol_names(symbols)
                .with_render_options(options)
                .decompile_class(dalvik_class_fmt)
        })
        .map(|output| {
            output.unwrap_or_else(|| radguard::writer::SourceOutput {
                source: format!(
                    "Error: Class {dalvik_class_fmt} not found in the reconstructed DEX."
                ),
                ..Default::default()
            })
        })
        .unwrap_or_else(|error| radguard::writer::SourceOutput {
            source: format!("/* RadGuard decompiler error: {error} */\n"),
            ..Default::default()
        })
}

#[cfg(test)]
mod tests {
    use super::{decompile_dex_bytes, decompile_dex_bytes_with_metadata};

    #[test]
    fn decompiles_with_radguard() {
        let dex = include_bytes!("../../../radguard/tests/fixtures/sample.dex");
        let source = decompile_dex_bytes(dex, "Lkotlinx/coroutines/flow/AbstractFlow$collect$1;");
        assert!(source.contains("class AbstractFlow$collect$1"));
    }

    #[test]
    fn reports_invalid_dex_without_panicking() {
        let source = decompile_dex_bytes(b"not a dex", "Lexample/Test;");
        assert!(source.starts_with("/* RadGuard decompiler error:"));
    }

    #[test]
    fn metadata_errors_do_not_panic() {
        let (source, references) =
            decompile_dex_bytes_with_metadata(b"not a dex", "Lexample/Test;");
        assert!(source.starts_with("/* RadGuard decompiler error:"));
        assert!(references.is_empty());
    }
}
