//! WIT file generation from compiled WASM binaries and Rust source files.
//!
//! Introspects a compiled `.wasm` binary to discover exports, then parses
//! Rust source files to extract rich type information and doc comments from
//! `#[wasm_bindgen]` annotated functions. The combined metadata is rendered
//! as a `.wit` file following the Component Model specification.

use std::fmt::Write as FmtWrite;
use std::path::Path;

use quote::ToTokens;

/// A parameter in a WIT function signature.
#[derive(Debug, Clone)]
pub struct WitParam {
    pub name: String,
    pub wit_type: String,
}

/// A function in a WIT interface.
#[derive(Debug, Clone)]
pub struct WitFunction {
    /// Function name in kebab-case (WIT convention).
    pub name: String,
    /// Documentation extracted from doc comments.
    pub docs: Option<String>,
    /// Function parameters with WIT types.
    pub params: Vec<WitParam>,
    /// Return type in WIT syntax, if any.
    pub return_type: Option<String>,
}

/// Configuration for WIT generation.
#[derive(Debug, Clone)]
pub struct WitConfig {
    /// WIT package name (e.g., "mycompany:my-module").
    pub package: String,
    /// WIT world name (e.g., "my-module").
    pub world: String,
    /// Interface name within the world (e.g., "api").
    pub interface_name: String,
}

impl Default for WitConfig {
    fn default() -> Self {
        Self {
            package: "local:module".to_string(),
            world: "module".to_string(),
            interface_name: "api".to_string(),
        }
    }
}

/// A complete WIT document ready to be rendered.
#[derive(Debug)]
pub struct WitDocument {
    pub config: WitConfig,
    pub functions: Vec<WitFunction>,
}

impl WitDocument {
    /// Render the WIT document as a `.wit` formatted string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        writeln!(out, "package {};", self.config.package).unwrap();
        writeln!(out).unwrap();

        writeln!(out, "interface {} {{", self.config.interface_name).unwrap();

        for (i, func) in self.functions.iter().enumerate() {
            if i > 0 {
                writeln!(out).unwrap();
            }

            if let Some(ref docs) = func.docs {
                for line in docs.lines() {
                    if line.is_empty() {
                        writeln!(out, "  ///").unwrap();
                    } else {
                        writeln!(out, "  /// {line}").unwrap();
                    }
                }
            }

            let params_str: String = func
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name, p.wit_type))
                .collect::<Vec<_>>()
                .join(", ");

            match &func.return_type {
                Some(ret) => {
                    writeln!(out, "  {}: func({params_str}) -> {ret};", func.name).unwrap()
                }
                None => writeln!(out, "  {}: func({params_str});", func.name).unwrap(),
            }
        }

        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "world {} {{", self.config.world).unwrap();
        writeln!(out, "  export {};", self.config.interface_name).unwrap();
        writeln!(out, "}}").unwrap();

        out
    }
}

/// Convert a snake_case name to kebab-case (WIT convention).
pub fn to_wit_name(name: &str) -> String {
    name.replace('_', "-")
}

/// Extract exported function names from a compiled WASM binary.
pub fn extract_wasm_exports(wasm_bytes: &[u8]) -> Result<Vec<String>, String> {
    use wasmparser::{ExternalKind, Parser, Payload};

    let parser = Parser::new(0);
    let mut exports = Vec::new();

    for payload in parser.parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| format!("Failed to parse WASM: {e}"))?;
        if let Payload::ExportSection(reader) = payload {
            for export in reader {
                let export = export.map_err(|e| format!("Failed to read export: {e}"))?;
                if matches!(export.kind, ExternalKind::Func) {
                    exports.push(export.name.to_string());
                }
            }
        }
    }

    Ok(exports)
}

/// Parse Rust source files in a directory to extract WIT function metadata.
///
/// Looks for functions annotated with `#[wasm_bindgen]` and extracts:
/// - Doc comments as descriptions
/// - Parameter names and types (mapped to WIT types)
/// - Return types (mapped to WIT types)
pub fn parse_rust_sources(src_dir: &Path) -> Result<Vec<WitFunction>, String> {
    use walkdir::WalkDir;

    let mut functions = Vec::new();

    for entry in WalkDir::new(src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "rs").unwrap_or(false))
    {
        let source = std::fs::read_to_string(entry.path())
            .map_err(|e| format!("Failed to read {}: {e}", entry.path().display()))?;

        let file = syn::parse_file(&source)
            .map_err(|e| format!("Failed to parse {}: {e}", entry.path().display()))?;

        for item in &file.items {
            match item {
                syn::Item::Fn(func) => {
                    if has_wasm_bindgen_attr(&func.attrs)
                        && is_pub(&func.vis)
                        && let Some(wit_func) = extract_function_metadata(&func.sig, &func.attrs)
                    {
                        functions.push(wit_func);
                    }
                }
                syn::Item::Impl(impl_block) => {
                    if has_wasm_bindgen_attr(&impl_block.attrs) {
                        for impl_item in &impl_block.items {
                            if let syn::ImplItem::Fn(method) = impl_item
                                && is_pub_impl(&method.vis)
                                && let Some(wit_func) =
                                    extract_function_metadata(&method.sig, &method.attrs)
                            {
                                functions.push(wit_func);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(functions)
}

/// Generate a WIT document from a compiled WASM binary and Rust source files.
///
/// 1. Extracts exported function names from the WASM binary
/// 2. Parses Rust source files for `#[wasm_bindgen]` functions with doc comments
/// 3. Matches source metadata to WASM exports
/// 4. Generates a WIT document for matched functions
pub fn generate_wit(
    wasm_bytes: &[u8],
    src_dir: &Path,
    config: WitConfig,
) -> Result<WitDocument, String> {
    let wasm_exports = extract_wasm_exports(wasm_bytes)?;
    let source_functions = parse_rust_sources(src_dir)?;

    // Match source functions to actual WASM exports.
    // wasm_bindgen mangles names in various ways, so we do a fuzzy match:
    // - exact match on snake_case name
    // - export ends with __<name> (method mangling)
    // - export contains the name (other mangling patterns)
    let functions: Vec<WitFunction> = source_functions
        .into_iter()
        .filter(|func| {
            let snake_name = func.name.replace('-', "_");
            wasm_exports.iter().any(|export| {
                export == &snake_name
                    || export.ends_with(&format!("__{snake_name}"))
                    || export.contains(&snake_name)
            })
        })
        .collect();

    Ok(WitDocument { config, functions })
}

/// Generate a WIT document from Rust source files only (no WASM binary validation).
///
/// Useful during development when the WASM binary may not exist yet.
pub fn generate_wit_from_source(src_dir: &Path, config: WitConfig) -> Result<WitDocument, String> {
    let functions = parse_rust_sources(src_dir)?;
    Ok(WitDocument { config, functions })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn has_wasm_bindgen_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        path.segments
            .last()
            .map(|s| s.ident == "wasm_bindgen")
            .unwrap_or(false)
    })
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn is_pub_impl(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn extract_doc_comments(attrs: &[syn::Attribute]) -> Option<String> {
    let docs: Vec<String> = attrs
        .iter()
        .filter_map(|attr| {
            if !attr.path().is_ident("doc") {
                return None;
            }
            if let syn::Meta::NameValue(nv) = &attr.meta
                && let syn::Expr::Lit(lit) = &nv.value
                && let syn::Lit::Str(s) = &lit.lit
            {
                return Some(s.value());
            }
            None
        })
        .collect();

    if docs.is_empty() {
        None
    } else {
        // rustc adds a leading space to doc comment content — trim it
        let trimmed: Vec<String> = docs
            .iter()
            .map(|line| {
                if let Some(stripped) = line.strip_prefix(' ') {
                    stripped.to_string()
                } else {
                    line.to_string()
                }
            })
            .collect();
        Some(trimmed.join("\n"))
    }
}

fn extract_function_metadata(
    sig: &syn::Signature,
    attrs: &[syn::Attribute],
) -> Option<WitFunction> {
    let name = to_wit_name(&sig.ident.to_string());
    let docs = extract_doc_comments(attrs);

    let params: Vec<WitParam> = sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(pat_type) = arg {
                let param_name = match pat_type.pat.as_ref() {
                    syn::Pat::Ident(ident) => to_wit_name(&ident.ident.to_string()),
                    _ => return None,
                };
                let wit_type = syn_type_to_wit(&pat_type.ty);
                Some(WitParam {
                    name: param_name,
                    wit_type,
                })
            } else {
                None // skip self params
            }
        })
        .collect();

    let return_type = match &sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ty) => {
            let wit = syn_type_to_wit(ty);
            if wit == "()" { None } else { Some(wit) }
        }
    };

    Some(WitFunction {
        name,
        docs,
        params,
        return_type,
    })
}

/// Map a Rust type (as parsed by syn) to a WIT type string.
fn syn_type_to_wit(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(type_path) => path_type_to_wit(type_path),
        syn::Type::Reference(type_ref) => ref_type_to_wit(type_ref),
        syn::Type::Tuple(tuple) if tuple.elems.is_empty() => "()".to_string(),
        other => {
            // Fallback: render the Rust type as a comment
            let rendered = other.to_token_stream().to_string();
            format!("/* {rendered} */")
        }
    }
}

fn path_type_to_wit(type_path: &syn::TypePath) -> String {
    let Some(segment) = type_path.path.segments.last() else {
        return "/* unknown */".to_string();
    };

    let ident = segment.ident.to_string();
    match ident.as_str() {
        "String" | "JsValue" => "string".to_string(),
        "bool" => "bool".to_string(),
        "u8" => "u8".to_string(),
        "u16" => "u16".to_string(),
        "u32" => "u32".to_string(),
        "u64" => "u64".to_string(),
        "i8" => "s8".to_string(),
        "i16" => "s16".to_string(),
        "i32" => "s32".to_string(),
        "i64" => "s64".to_string(),
        "f32" => "f32".to_string(),
        "f64" => "f64".to_string(),
        "Vec" => {
            let inner = extract_first_generic_arg(segment);
            format!("list<{inner}>")
        }
        "Option" => {
            let inner = extract_first_generic_arg(segment);
            format!("option<{inner}>")
        }
        "Result" => {
            let args = extract_generic_args(segment);
            match args.len() {
                2 => format!("result<{}, {}>", args[0], args[1]),
                1 => format!("result<{}>", args[0]),
                _ => "result".to_string(),
            }
        }
        // Custom/unknown types — convert to kebab-case as a WIT type reference
        other => to_wit_name(other),
    }
}

fn ref_type_to_wit(type_ref: &syn::TypeReference) -> String {
    match type_ref.elem.as_ref() {
        syn::Type::Path(p) if p.path.is_ident("str") => "string".to_string(),
        syn::Type::Slice(s) => format!("list<{}>", syn_type_to_wit(&s.elem)),
        other => syn_type_to_wit(other),
    }
}

fn extract_first_generic_arg(segment: &syn::PathSegment) -> String {
    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return syn_type_to_wit(inner);
    }
    "/* unknown */".to_string()
}

fn extract_generic_args(segment: &syn::PathSegment) -> Vec<String> {
    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
        return args
            .args
            .iter()
            .filter_map(|a| {
                if let syn::GenericArgument::Type(t) = a {
                    Some(syn_type_to_wit(t))
                } else {
                    None
                }
            })
            .collect();
    }
    Vec::new()
}
