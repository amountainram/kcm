use openapiv3::OpenAPI;
use std::{
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

    let code = type_space.to_stream().to_string();
    let out_path = Path::new(&std::env::var("OUT_DIR").unwrap()).join("keycloak.rs");
    fs::write(&out_path, code).expect("failed to write openapi keycloak structs");
}
