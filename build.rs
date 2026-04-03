use openapiv3::OpenAPI;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use typify::{TypeSpace, TypeSpaceSettings};

const KEYCLOAK_VERSION: &str = "26.5.6";

fn keycloak_openapi_url() -> String {
    format!("https://www.keycloak.org/docs-api/{KEYCLOAK_VERSION}/rest-api/openapi.json")
}

fn prepare_openapi_spec() -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let spec_path = Path::new(&out_dir).join(format!("keycloak-openapi-{}.json", KEYCLOAK_VERSION));

    // Download only if not already cached
    if !spec_path.exists() {
        let resp = ureq::get(&keycloak_openapi_url())
            .call()
            .expect("failed to download openapi spec");
        let body = resp
            .into_body()
            .read_to_string()
            .expect("failed to read response body");
        fs::write(&spec_path, &body).expect("failed to write openapi spec");
    }

    spec_path
}

fn main() {
    let spec_path = prepare_openapi_spec();

    let spec: OpenAPI = serde_json::from_str(
        &fs::read_to_string(&spec_path).expect("failed to read openapi spec file"),
    )
    .expect("failed to parse openapi spec");

    let mut type_space = TypeSpace::new(
        TypeSpaceSettings::default()
            .with_derive("Debug".into())
            .with_derive("Clone".into())
            .with_attr("#[allow(unused)]".into()),
    );

    // Add all schemas from the spec together so $ref cross-references resolve
    if let Some(components) = &spec.components {
        let type_defs: Vec<(String, schemars::schema::Schema)> = components
            .schemas
            .iter()
            .filter_map(|(name, schema_ref)| {
                if let openapiv3::ReferenceOr::Item(schema) = schema_ref {
                    let json = serde_json::to_value(schema).unwrap();
                    let schemars_schema: schemars::schema::Schema =
                        serde_json::from_value(json).unwrap();
                    Some((name.clone(), schemars_schema))
                } else {
                    None
                }
            })
            .collect();
        type_space
            .add_ref_types(type_defs)
            .expect("failed to add schema types");
    }

    let types_code = type_space.to_stream().to_string();
    let paths_code = generate_paths(&spec);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("keycloak.rs"), types_code)
        .expect("failed to write openapi keycloak structs");
    fs::write(out_dir.join("keycloak_paths.rs"), paths_code)
        .expect("failed to write openapi keycloak paths");
}

fn to_snake_case(s: &str) -> String {
    let s = s.replace('-', "_");
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}

fn generate_paths(spec: &OpenAPI) -> String {
    let mut functions = BTreeMap::new();

    let reserved = [
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ];

    for (path, path_ref) in &spec.paths.paths {
        let path_item = match path_ref {
            openapiv3::ReferenceOr::Item(item) => item,
            _ => continue,
        };

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        let mut name_parts = Vec::new();
        let mut params: Vec<(String, String)> = Vec::new();
        let mut seen_params = std::collections::HashMap::new();

        for seg in &segments {
            if let Some(param) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                let mut rust_param = to_snake_case(param);

                // Deduplicate param names
                let count = seen_params.entry(rust_param.clone()).or_insert(0usize);
                *count += 1;
                if *count > 1 {
                    rust_param = format!("{}_{}", rust_param, count);
                }

                // Escape reserved keywords
                let arg_name = if reserved.contains(&rust_param.as_str()) {
                    format!("r#{rust_param}")
                } else {
                    rust_param.clone()
                };

                name_parts.push(rust_param.clone());
                params.push((arg_name, param.to_string()));
            } else {
                name_parts.push(to_snake_case(seg));
            }
        }

        let base_name = if name_parts.is_empty() {
            "root".to_string()
        } else {
            let joined = name_parts.join("_");
            joined.strip_prefix("admin_").unwrap_or(&joined).to_string()
        };

        let param_args: String = params
            .iter()
            .map(|(rust_name, _)| format!("{rust_name}: &str"))
            .collect::<Vec<_>>()
            .join(", ");

        // Replace {original-param} with {rust_param} in the format string
        // Process in reverse order so that duplicates (e.g. second client-uuid)
        // are replaced correctly.
        let mut fmt_path = path.clone();
        for (rust_name, orig_name) in params.iter().rev() {
            let rust_name = rust_name.strip_prefix("r#").unwrap_or(rust_name);
            // Replace last occurrence to handle duplicates correctly
            if let Some(pos) = fmt_path.rfind(&format!("{{{orig_name}}}")) {
                fmt_path.replace_range(pos..pos + orig_name.len() + 2, &format!("{{{rust_name}}}"));
            }
        }

        let methods: &[(&str, &Option<openapiv3::Operation>)] = &[
            ("get", &path_item.get),
            ("post", &path_item.post),
            ("put", &path_item.put),
            ("delete", &path_item.delete),
            ("patch", &path_item.patch),
        ];

        for (method, op) in methods {
            let op = match op {
                Some(op) => op,
                None => continue,
            };

            let fn_name = format!("{base_name}_{method}");

            let mut doc = String::new();
            if let Some(summary) = &op.summary {
                for line in summary.trim().lines() {
                    doc.push_str(&format!("    /// {}\n", line));
                }
            }
            if let Some(description) = &op.description {
                if !description.is_empty() {
                    if !doc.is_empty() {
                        doc.push_str("    ///\n");
                    }
                    for line in description.trim().lines() {
                        doc.push_str(&format!("    /// {}\n", line));
                    }
                }
            }

            functions.insert(
                fn_name.clone(),
                format!(
                    "{doc}    pub fn {fn_name}({param_args}) -> String {{\n        \
                     format!(\"{fmt_path}\")\n    }}"
                ),
            );
        }
    }

    let mut code = String::from("#[allow(unused)]\npub mod paths {\n");
    for func in functions.values() {
        code.push_str(func);
        code.push('\n');
    }
    code.push_str("}\n");
    code
}
