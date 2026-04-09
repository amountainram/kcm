use crate::{Error, Result, cli::OutputFormat, client::AuthAccessToken, out, outfmt};
pub use colored::Color;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    env, fmt, fs,
    io::{self, Write, stdout},
    path::{Path, PathBuf},
};
use tracing::error;
use typed_builder::TypedBuilder;

pub mod authorize;
pub mod clients;
pub mod context;

pub const KCM_CONFIG: &str = "KCM_CONFIG";

#[derive(Deserialize, Serialize, Clone)]
pub struct Sensitive<T = String>(T);

impl<T> Sensitive<T> {
    pub fn read(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

fn deserialize_server_url<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .map(|s| s.strip_suffix('/').map(String::from).unwrap_or(s)))
}

fn default_auth_realm() -> String {
    "master".to_string()
}

#[derive(Default, Clone, Deserialize, Serialize)]
pub struct Context {
    #[serde(
        rename = "server-url",
        alias = "server_url",
        alias = "serverUrl",
        default,
        deserialize_with = "deserialize_server_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_url: Option<String>,
    #[serde(rename = "realm", default = "default_auth_realm")]
    pub realm: String,
    #[serde(rename = "working-realm", skip_serializing_if = "Option::is_none")]
    pub working_realm: Option<String>,
    #[serde(rename = "username", skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "password", skip_serializing_if = "Option::is_none")]
    pub password: Option<Sensitive>,
    #[serde(rename = "token", skip_serializing_if = "Option::is_none")]
    pub token: Option<Sensitive>,
}

const KEYRING_SERVICE: &str = "kcm";

impl Context {
    fn keyring_entry(name: &str, field: &str) -> Result<keyring::Entry> {
        let key = format!("{name}/{field}");
        Ok(keyring::Entry::new(KEYRING_SERVICE, &key)?)
    }

    fn keyring_read(key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)?;
        match entry.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn keyring_remove(key: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::from(e)),
        }
    }

    pub fn set_password(&mut self, name: &str, value: &str) -> Result<()> {
        let entry = Self::keyring_entry(name, "password").inspect_err(
            |error| error!(%error, name, "failed to reserve password entry in OS keyring"),
        )?;
        entry
            .set_password(value)
            .inspect_err(|error| error!(%error, name, "failed to store password in OS keyring"))?;
        self.password = Some(Sensitive::from(format!("{name}/password")));
        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        match &self.password {
            Some(key_ref) => Self::keyring_read(key_ref.read()).inspect_err(|error| {
                error!(%error, "failed to retrieve password from OS keyring");
            }),
            None => Ok(None),
        }
    }

    pub fn set_token(&mut self, name: &str, at: &AuthAccessToken) -> Result<()> {
        let value = &serde_json::to_vec(&at)
            .inspect_err(|error| error!(%error, name, "failed to serialize token"))?;
        let entry = Self::keyring_entry(name, "token").inspect_err(
            |error| error!(%error, name, "failed to reserve token entry in OS keyring"),
        )?;
        entry
            .set_secret(&value)
            .inspect_err(|error| error!(%error, name, "failed to store token in OS keyring"))?;
        self.token = Some(Sensitive::from(format!("{name}/token")));

        Ok(())
    }

    pub fn delete_token(&self) -> Result<()> {
        if let Some(key_ref) = &self.token {
            Self::keyring_remove(key_ref.read())
                .inspect_err(|error| error!(%error, "failed to remove token from OS keyring"))?;
        }

        Ok(())
    }

    pub fn get_token(&self) -> Result<Option<AuthAccessToken>> {
        match &self.token {
            Some(key_ref) => Self::keyring_read(key_ref.read())
                .inspect_err(|error| {
                    error!(%error, "failed to retrieve token from OS keyring");
                })
                .map_err(Error::from)
                .and_then(|at| match at {
                    None => Ok(None),
                    Some(at) => Ok(Some(
                        serde_json::from_str(&at)
                            .inspect_err(|error| {
                                error!(%error, "failed to deserialize token from OS keyring");
                            })
                            .map_err(Error::from)?,
                    )),
                }),
            None => Ok(None),
        }
    }

    pub fn delete_secrets(&self) -> Result<()> {
        if let Some(key_ref) = &self.password {
            Self::keyring_remove(key_ref.read())
                .inspect_err(|error| error!(%error, "failed to remove password from OS keyring"))?;
        }
        if let Some(key_ref) = &self.token {
            Self::keyring_remove(key_ref.read())
                .inspect_err(|error| error!(%error, "failed to remove token from OS keyring"))?;
        }
        Ok(())
    }
}

#[derive(Default, Deserialize, Serialize)]
struct Config {
    #[serde(
        rename = "current-context",
        alias = "current_context",
        alias = "currentContext",
        skip_serializing_if = "Option::is_none"
    )]
    current_context: Option<String>,
    #[serde(rename = "contexts", default)]
    contexts: BTreeMap<String, Context>,
}

fn build_config_path() -> Result<PathBuf> {
    Ok(env::var(KCM_CONFIG)
        .map(Into::into)
        .or_else(|e| {
            if matches!(e, env::VarError::NotPresent) {
                Ok(dirs::config_dir()
                    .ok_or_else(|| {
                        error!(env = KCM_CONFIG, "failed to find a default config dir");
                        Error::InvalidConfigDir
                    })?
                    .join("kcm")
                    .join("config.json"))
            } else {
                Err(Error::from(e))
            }
        })
        .inspect_err(|error| {
            error!(
                env = KCM_CONFIG,
                %error,
                "failed to parse environment variable"
            );
        })?)
}

fn print_path(path: &Path) -> Cow<'_, str> {
    String::from_utf8_lossy(path.as_os_str().as_encoded_bytes())
}

fn load_config() -> Result<Config> {
    let path = build_config_path()?;

    fs::read_to_string(&path).map_or_else(
        |error| {
            if matches!(error.kind(), io::ErrorKind::NotFound) {
                Ok(Default::default())
            } else {
                error!(
                    path = %print_path(&path),
                    %error,
                    "failed to read configuration file",
                );
                Err(Error::from(error))
            }
        },
        |c| {
            Ok(serde_json::from_str(&c).inspect_err(|error| {
                error!(path = %print_path(&path), %error, "invalid configuration file");
            })?)
        },
    )
}

fn save_config(config: &Config) -> Result<()> {
    let path = build_config_path()?;
    let dir = path.parent().ok_or_else(|| {
        error!(
            path = %print_path(&path),
            "configuration path must have a parent folder",
        );
        Error::InvalidParentPath
    })?;
    if dir.exists() && !dir.is_dir() {
        let error = Error::msg("invalid parent path");
        error!(
            path = %print_path(&path),
            %error,
            "configuration path parent must be a folder",
        );
        return Err(Error::InvalidParentPath);
    }
    fs::create_dir_all(dir).inspect_err(|error| {
        error!(path = %print_path(dir), %error, "failed to create configuration file directory")
    })?;
    fs::write(
        &path,
        serde_json::to_string_pretty(config)
            .inspect_err(|error| {
                error!(path = %print_path(&path), %error, "configuration content is an invalid json")
            })?,
    )
    .inspect_err(|error| {
        error!(
            path = %print_path(&path),
            %error,
            "failed to write configuration to file",
        )
    })?;

    Ok(())
}

fn current_context() -> Result<Option<(String, Context)>> {
    let mut config =
        load_config().inspect_err(|error| error!(%error, "failed to load configuration"))?;
    Ok(config
        .current_context
        .map(|name| {
            config
                .contexts
                .remove(&name)
                .map(|context| (name.clone(), context))
                .ok_or_else(|| Error::ContextNotFound)
        })
        .transpose()?)
}

fn enforce_context(format: OutputFormat) -> Result<(String, Context)> {
    current_context()
        .inspect_err(|err| {
            if matches!(err, Error::ContextNotFound) {
                outfmt!(
                    format,
                    r#"no current context configured —  \
                    select one with "context use""#
                );
            }
        })?
        .ok_or_else(|| {
            outfmt!(format, "no active context");
            Error::ContextSelection
        })
}

fn load_context_or_current(name: Option<&str>) -> Result<(String, Context, Config)> {
    let config = load_config()?;
    let context_entry = name.and_then(|name| {
        config
            .contexts
            .get(name)
            .map(|context| (name.to_string(), context.clone()))
    });

    match context_entry {
        Some((name, context)) => Ok((name, context, config)),
        None => {
            let ctx = current_context().inspect_err(|error| {
                error!(%error, "failed to load current context");
            })?;
            ctx.map(|(name, context)| (name, context, config))
                .ok_or_else(|| Error::ContextSelection)
        }
    }
}

const LABEL_WIDTH: usize = 20;

#[derive(Default, TypedBuilder)]
struct Printer {
    #[builder(default)]
    format: OutputFormat,
    #[builder(default, setter(skip))]
    buffer: serde_json::Map<String, serde_json::Value>,
}

impl Drop for Printer {
    fn drop(&mut self) {
        match self.format {
            OutputFormat::Plain => {
                let _ = stdout().flush();
            }
            OutputFormat::Json => {
                out!(
                    "{}",
                    serde_json::to_string_pretty(&self.buffer)
                        .inspect_err(|error| {
                            error!(%error, "failed to serialize token claims");
                        })
                        .unwrap_or_default()
                );
            }
        }
    }
}

impl Printer {
    pub fn ln(&self) {
        if matches!(self.format, OutputFormat::Plain) {
            out!();
        }
    }

    pub fn print_field<K, V>(&mut self, label: K, value: V)
    where
        K: fmt::Display + Into<String>,
        V: fmt::Display + Clone + Into<serde_json::Value>,
    {
        use colored::Colorize;

        const LABEL_WIDTH: usize = 20;

        match self.format {
            OutputFormat::Plain => {
                let label = format!("{label}:");
                out!(
                    "    {} {value}",
                    format!("{label:<width$}", width = LABEL_WIDTH).dimmed(),
                );
            }
            OutputFormat::Json => {
                self.buffer.insert(label.into(), value.clone().into());
            }
        }
    }

    pub fn print_field_with_color<K, V>(&mut self, label: K, value: V, color: colored::Color)
    where
        K: fmt::Display + Into<String>,
        V: fmt::Display + Clone + Into<serde_json::Value>,
    {
        use colored::Colorize;

        match self.format {
            OutputFormat::Plain => {
                let label = format!("{label}:");
                let value = value.to_string().color(color);
                out!(
                    "    {} {value}",
                    format!("{label:<width$}", width = LABEL_WIDTH).dimmed(),
                );
            }
            OutputFormat::Json => {
                self.print_field(label, value);
            }
        }
    }
}
