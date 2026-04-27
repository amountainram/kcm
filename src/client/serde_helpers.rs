pub mod bool_as_string {
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.and_then(|v| v.parse().ok()))
    }

    pub fn serialize<S>(value: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value {
            Some(true) => serializer.serialize_str("true"),
            Some(false) => serializer.serialize_str("false"),
            None => serializer.serialize_none(),
        }
    }
}

pub mod i64_as_string {
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.and_then(|v| v.parse().ok()))
    }

    pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value {
            Some(n) => serializer.serialize_str(&n.to_string()),
            None => serializer.serialize_none(),
        }
    }
}

pub mod jwks_as_string {
    use jsonwebtoken::jwk::JwkSet;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<JwkSet>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(<D::Error as serde::de::Error>::custom)?)
    }

    pub fn serialize<S>(value: &Option<JwkSet>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value.as_ref() {
            Some(set) => {
                let json_str =
                    serde_json::to_string(set).map_err(serde::ser::Error::custom)?;
                serializer.serialize_str(&json_str)
            }
            None => serializer.serialize_none(),
        }
    }
}

/// Converts a serde-serializable config struct into a flat `HashMap<String, String>`.
///
/// Both `ClientAttributes` and `IdentityProviderConfig` follow the same pattern:
/// serialize to a JSON object, then collect string-valued entries.
pub fn config_to_string_map<T: serde::Serialize>(
    value: &T,
) -> std::collections::HashMap<String, String> {
    serde_json::to_value(value)
        .map(|v| match v {
            serde_json::Value::Object(o) => o,
            _ => Default::default(),
        })
        .map(|o| {
            o.into_iter()
                .filter_map(|(k, v)| match v {
                    serde_json::Value::String(s) => Some((k, s)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Same as [`config_to_string_map`] but for structs whose values are arrays of strings
/// (e.g. `UserAttributes`).
pub fn config_to_string_vec_map<T: serde::Serialize>(
    value: &T,
) -> std::collections::HashMap<String, Vec<String>> {
    serde_json::to_value(value)
        .map(|v| match v {
            serde_json::Value::Object(o) => o,
            _ => Default::default(),
        })
        .map(|o| {
            o.into_iter()
                .filter_map(|(k, v)| match v {
                    serde_json::Value::Array(s) => Some((
                        k,
                        s.into_iter()
                            .filter_map(|v| match v {
                                serde_json::Value::String(s) => Some(s),
                                _ => None,
                            })
                            .collect(),
                    )),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}
