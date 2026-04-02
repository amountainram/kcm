use crate::{Context as _, Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    env, fmt, fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tracing::{error, info};

pub const KCM_CONFIG: &str = "KCM_CONFIG";

#[derive(Deserialize, Serialize)]
struct Sensitive<T = String>(T);

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

#[derive(Default, Deserialize, Serialize)]
struct Context {
    #[serde(
        rename = "server-url",
        alias = "server_url",
        alias = "serverUrl",
        skip_serializing_if = "Option::is_none"
    )]
    server_url: Option<String>,
    #[serde(rename = "realm", skip_serializing_if = "Option::is_none")]
    realm: Option<String>,
    #[serde(rename = "username", skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(rename = "password", skip_serializing_if = "Option::is_none")]
    password: Option<Sensitive>,
    #[serde(rename = "token", skip_serializing_if = "Option::is_none")]
    token: Option<Sensitive>,
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

fn print_context(name: &str, ctx: &Context, active: bool) {
    use colored::Colorize;

    let marker = if active {
        format!("{} ", "*".green())
    } else {
        "  ".into()
    };
    let label = if active {
        name.bold().to_string()
    } else {
        name.to_string()
    };
    println!("{marker}{label}");

    if let Some(server) = &ctx.server_url {
        println!("    {} {server}", "server-url:".dimmed());
    }
    if let Some(realm) = &ctx.realm {
        println!("    {} {realm}", "realm:".dimmed());
    }
    if let Some(user) = &ctx.username {
        println!("    {} {user}", "username:".dimmed());
    }
    if let Some(pass) = &ctx.password {
        println!("    {} {pass}", "password:".dimmed());
    }
    if let Some(token) = &ctx.token {
        println!("    {} {token}", "token:".dimmed());
    }
}

fn prompt_password(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        return Err(Error::msg(
            "password required: provide a value or run interactively",
        ));
    }
    eprint!("{prompt}");
    io::stderr().flush()?;
    let password = rpassword::read_password().with_context(|| "failed to read password")?;
    Ok(password.trim().to_string())
}

fn resolve_password(password: Option<String>) -> Result<Option<String>> {
    match password {
        None => Ok(None),
        Some(p) if p.is_empty() => prompt_password("Password: ").map(Some),
        Some(p) => Ok(Some(p)),
    }
}

fn confirm(message: &str) -> Result<bool> {
    eprint!("{message} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

fn has_fzf() -> bool {
    Command::new("which")
        .arg("fzf")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn fzf_select(input: &str, current: Option<&str>) -> Result<Option<String>> {
    let mut args = vec!["--height=40%".to_string()];
    let mut child = Command::new("fzf");
    child.args(["--tac", "--cycle"]);
    if let Some(cur) = current {
        args.push(format!("--header=current: {cur}"));
    }
    let child = child
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| "failed to spawn fzf")?;

    io::Write::write_all(&mut child.stdin.as_ref().unwrap(), input.as_bytes())?;
    let output = child.wait_with_output().with_context(|| "fzf failed")?;

    if !output.status.success() {
        return Ok(None); // user cancelled (Esc / Ctrl-C)
    }
    let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if selected.is_empty() {
        None
    } else {
        Some(selected)
    })
}

pub fn r#use(name: Option<String>) -> Result<()> {
    let mut config = load_config().with_context(|| "while loading configuration")?;

    if config.contexts.is_empty() {
        return Err(Error::msg(
            r#"no contexts configured — create one with "context create""#,
        ));
    }

    let selected = match name {
        Some(n) => n,
        None => {
            let names = config
                .contexts
                .keys()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .join("\n");
            if io::stdin().is_terminal() && has_fzf() {
                match fzf_select(&names, config.current_context.as_deref())? {
                    Some(s) => s,
                    None => {
                        info!("no selection");
                        return Ok(());
                    }
                }
            } else {
                return Err(Error::msg(
                    "context name required (fzf not \
                     available for interactive selection)",
                ));
            }
        }
    };

    if !config.contexts.contains_key(&selected) {
        return Err(Error::msg(format!("context \"{selected}\" not found")));
    }

    config.current_context = Some(selected.clone());
    save_config(&config).with_context(|| "while saving configuration")?;
    info!(name = selected, "switched to context");

    Ok(())
}

pub fn show() -> Result<()> {
    if let Some((name, current_context)) =
        current_context().with_context(|| "while loading configuration")?
    {
        println!();
        print_context(&name, &current_context, true);
        println!();
    } else {
        eprintln!("no active context");
    }
    Ok(())
}

pub fn create(
    name: String,
    current: bool,
    server_url: Option<String>,
    realm: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let mut config = load_config().with_context(|| "while loading configuration")?;
    if config.contexts.contains_key(&name) {
        let error = Error::msg("context already exists");
        error!(
            name,
            ?error,
            r#"context already exists — use "context update" to modify it"#
        );
        return Err(error);
    }

    let password = resolve_password(password)
        .with_context(|| "while reading password")?
        .map(Into::into);

    if current {
        let _ = config.current_context.insert(name.clone());
    }
    config.contexts.insert(
        name.clone(),
        Context {
            server_url,
            realm,
            username,
            password,
            token: token.map(Into::into),
        },
    );

    save_config(&config).with_context(|| "while saving configuration")?;

    info!(name, "context created");

    Ok(())
}

pub fn update(
    name: Option<String>,
    current: bool,
    server_url: Option<String>,
    realm: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let Config {
        mut current_context,
        mut contexts,
    } = load_config().with_context(|| "while loading configuration")?;
    let name = match name.or(current_context.clone()) {
        Some(x) => x,
        None => {
            let error = Error::msg("no context name");
            eprintln!(
                r#"no context name given and no active context — pass a name or set one with "context use""#
            );
            return Err(error);
        }
    };
    if let Some(entry) = contexts.get_mut(&name) {
        let password = resolve_password(password)
            .with_context(|| "while reading password")?
            .map(Into::into);

        if current {
            let _ = current_context.insert(name.clone());
        }
        if let Some(server_url) = server_url {
            let _ = entry.server_url.insert(server_url);
        }
        if let Some(realm) = realm {
            let _ = entry.realm.insert(realm);
        }
        if let Some(username) = username {
            let _ = entry.username.insert(username);
        }
        if let Some(password) = password {
            let _ = entry.password.insert(password);
        }
        if let Some(token) = token {
            let _ = entry.token.insert(token.into());
        }

        save_config(&Config {
            current_context,
            contexts,
        })
        .with_context(|| "while saving configuration")?;

        info!(name, "context created");

        Ok(())
    } else {
        let error = Error::msg("context does not exist");
        eprintln!(r#"context "{name}" not found — use "context create" to add it"#,);
        return Err(error);
    }
}

pub fn delete(yes: bool, name: String) -> Result<()> {
    let mut config = load_config().with_context(|| "while loading configuration")?;
    if !yes {
        if !confirm(&format!("delete context \"{name}\"?"))? {
            info!("aborted");
            return Ok(());
        }
    }

    if config.current_context.as_ref() == Some(&name) {
        config.current_context.take();
    }
    if config.contexts.remove(&name).is_none() {
        let error = Error::msg("context not found");
        error!(name, ?error, "context not found");
        return Err(error);
    }

    save_config(&config).with_context(|| "while saving configuration")?;

    info!(name, "context deleted");

    Ok(())
}

pub fn list() -> Result<()> {
    let config = load_config().with_context(|| "while loading configuration")?;

    if config.contexts.is_empty() {
        eprintln!("no context configured");
        return Ok(());
    }

    println!();
    for (name, ctx) in config.contexts.iter() {
        print_context(name, ctx, Some(name) == config.current_context.as_ref());
    }
    println!();

    Ok(())
}
