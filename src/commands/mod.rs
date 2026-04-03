use crate::{Context as _, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    env, fmt, fs, io,
    path::{Path, PathBuf},
};
use tracing::error;

pub mod authorize;
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

#[derive(Default, Clone, Deserialize, Serialize)]
pub struct Context {
    #[serde(
        rename = "server-url",
        alias = "server_url",
        alias = "serverUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_url: Option<String>,
    #[serde(rename = "realm", skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
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
        keyring::Entry::new(KEYRING_SERVICE, &key)
            .map_err(|e| Error::msg(format!("keyring error: {e}")))
    }

    fn keyring_read(key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| Error::msg(format!("keyring error: {e}")))?;
        match entry.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::msg(format!("failed to read from keyring: {e}"))),
        }
    }

    fn keyring_remove(key: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|e| Error::msg(format!("keyring error: {e}")))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::msg(format!("failed to delete from keyring: {e}"))),
        }
    }

    pub fn set_password(&mut self, name: &str, value: &str) -> Result<()> {
        let entry = Self::keyring_entry(name, "password")?;
        entry
            .set_password(value)
            .map_err(|e| Error::msg(format!("failed to store password in keyring: {e}")))?;
        self.password = Some(Sensitive::from(format!("{name}/password")));
        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        match &self.password {
            Some(key_ref) => Self::keyring_read(key_ref.read()),
            None => Ok(None),
        }
    }

    pub fn set_token(&mut self, name: &str, value: &str) -> Result<()> {
        let entry = Self::keyring_entry(name, "token")?;
        entry
            .set_password(value)
            .map_err(|e| Error::msg(format!("failed to store token in keyring: {e}")))?;
        self.token = Some(Sensitive::from(format!("{name}/token")));
        Ok(())
    }

    pub fn delete_token(&self) -> Result<()> {
        if let Some(key_ref) = &self.token {
            Self::keyring_remove(key_ref.read())?;
        }
        Ok(())
    }

    pub fn get_token(&self) -> Result<Option<String>> {
        match &self.token {
            Some(key_ref) => Self::keyring_read(key_ref.read()),
            None => Ok(None),
        }
    }

    pub fn delete_secrets(&self) -> Result<()> {
        if let Some(key_ref) = &self.password {
            Self::keyring_remove(key_ref.read())?;
        }
        if let Some(key_ref) = &self.token {
            Self::keyring_remove(key_ref.read())?;
        }
        Ok(())
    }

    pub fn resolved(&self) -> Result<Self> {
        let mut copy = self.clone();
        if let Some(pw) = self.get_password()? {
            copy.password = Some(pw.into());
        }
        if let Some(tok) = self.get_token()? {
            copy.token = Some(tok.into());
        }
        Ok(copy)
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
                        let error = Error::msg("invalid config dir");
                        error!(
                            env = KCM_CONFIG,
                            ?error,
                            "failed to find a defautl config dir"
                        );
                        error
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
                ?error,
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
                    ?error,
                    "failed to read configuration file",
                );
                Err(Error::from(error))
            }
        },
        |c| {
            Ok(serde_json::from_str(&c).inspect_err(|error| {
                error!(path = %print_path(&path), ?error, "invalid configuration file");
            })?)
        },
    )
}

fn save_config(config: &Config) -> Result<()> {
    let path = build_config_path()?;
    let dir = path.parent().ok_or_else(|| {
        let error = Error::msg("invalid parent path");
        error!(
            path = %print_path(&path),
            ?error,
            "configuration path must have a parent folder",
        );

        error
    })?;
    if dir.exists() && !dir.is_dir() {
        let error = Error::msg("invalid parent path");
        error!(
            path = %print_path(&path),
            ?error,
            "configuration path parent must be a folder",
        );
        return Err(error);
    }
    fs::create_dir_all(dir).inspect_err(|error| error!(path = %print_path(dir), ?error, "failed to create configuration file directory"))?;
    fs::write(
        &path,
        serde_json::to_string_pretty(config).inspect_err(|error| error!(path = %print_path(&path), ?error, "configuration content is an invalid json"))?,
    )
    .inspect_err(|e| {
        error!(
            "failed to write configuration to file '{}': {e:?}",
            print_path(&path)
        )
    })?;

    Ok(())
}

fn current_context() -> Result<Option<(String, Context)>> {
    let mut config = load_config().with_context(|| "while loading configuration")?;
    Ok(config
        .current_context
        .map(|name| {
            config
                .contexts
                .remove(&name)
                .map(|context| (name, context))
                .ok_or_else(|| {
                    let error = Error::msg("current context not found in configuration");
                    error!(?error, "invalid configuration");
                    error
                })
        })
        .transpose()?)
}

fn load_context_or_current(name: Option<&str>) -> Result<(String, Context, Config)> {
    let config = load_config().with_context(|| "while loading configuration")?;
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
                error!(?error, "failed to load current context");
            })?;
            ctx.map(|(name, context)| (name, context, config)).ok_or_else(|| {
                let error = Error::msg("no context name");
                println!(
                    r#"no context name given and no active context — pass a name or set one with "context use""#
                );
                error
            })
        }
    }
}

fn coalesce_realm<'a>(ctx: &'a Context, realm: Option<&'a str>) -> Option<&'a str> {
    ctx.realm.as_deref().or(realm)
}
