use super::{Config, Context, current_context, load_config, save_config};
use crate::{Error, Result, cli::OutputFormat, out, outfmt};
use std::{
    io::{IsTerminal, Write, stderr, stdin},
    process::{Command, Stdio},
};
use tracing::error;

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
    out!("{marker}{label}");

    if let Some(server) = &ctx.server_url {
        out!("    {} {server}", "server-url:".dimmed());
    }
    if let Some(realm) = &ctx.realm {
        out!("    {} {realm}", "realm:".dimmed());
    }
    if let Some(user) = &ctx.username {
        out!("    {} {user}", "username:".dimmed());
    }
    if let Some(pass) = &ctx.password {
        out!("    {} {pass}", "password:".dimmed());
    }
    if let Some(token) = &ctx.token {
        out!("    {} {token}", "token:".dimmed());
    }
}

fn prompt_password(prompt: &str) -> Result<String> {
    if !stdin().is_terminal() {
        out!("password required: provide a value or run interactively");
        return Err(Error::NoStdin);
    }

    eprint!("{prompt}");
    stderr().flush()?;

    let password = rpassword::read_password()
        .inspect_err(|error| error!(%error, "failed to read password"))?;
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
    stderr().flush()?;
    let mut answer = String::new();
    stdin().read_line(&mut answer).inspect_err(|error| {
        error!(%error, "failed to read confirmation prompt");
    })?;
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
        .inspect_err(|error| {
            error!(%error, input, ?current, "failed to spawn fzf");
        })?;

    Write::write_all(&mut child.stdin.as_ref().unwrap(), input.as_bytes()).inspect_err(
        |error| {
            error!(%error, input, ?current, "falied to select from fzf");
        },
    )?;
    let output = child
        .wait_with_output()
        .inspect_err(|error| error!(%error, "fzf failed"))?;

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
    let mut config = load_config()?;

    if config.contexts.is_empty() {
        out!(r#"no contexts configured —  create one with "context create""#);
        return Err(Error::ContextNotFound);
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
            if stdin().is_terminal() && has_fzf() {
                match fzf_select(&names, config.current_context.as_deref())? {
                    Some(s) => s,
                    None => {
                        out!("nothing selected");
                        return Ok(());
                    }
                }
            } else {
                out!(
                    "context name required (fzf not \
                     available for interactive selection)",
                );
                return Err(Error::ContextNameRequired);
            }
        }
    };

    if !config.contexts.contains_key(&selected) {
        out!(
            r#"context '{selected}' not found —  \
              select one with "context use""#
        );
        return Err(Error::ContextSelection);
    }

    config.current_context = Some(selected.clone());
    save_config(&config)?;
    out!("switched to context '{selected}'");

    Ok(())
}

pub fn show(format: OutputFormat) -> Result<()> {
    if let Some((name, current_context)) = current_context().inspect_err(|err| {
        if matches!(err, Error::ContextNotFound) {
            outfmt!(
                format,
                r#"no current context configured —  \
                    select one with "context use""#
            );
        }
    })? {
        match format {
            OutputFormat::Json => {
                let mut map = serde_json::Map::new();
                map.insert("name".into(), name.clone().into());
                map.insert(
                    "context".into(),
                    serde_json::to_value(&current_context).inspect_err(
                        |error| error!(%error, %format, name, "failed to deserialize context"),
                    )?,
                );
                out!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Object(map))
                        .inspect_err(|error| {
                            error!(%error, %format, name, "failed to serialize configuration context")
                        })?
                );
            }
            OutputFormat::Plain => {
                out!();
                print_context(&name, &current_context, true);
                out!();
            }
        }
    } else {
        outfmt!(format, "no active context");
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
    let mut config = load_config()?;
    if config.contexts.contains_key(&name) {
        out!(
            "context already exists —  \
             use \"context update\" to modify it"
        );

        return Err(Error::ContextAlreadyExists);
    }

    let password = resolve_password(password)?;

    let mut ctx = Context {
        server_url,
        realm,
        username,
        password: None,
        token: None,
    };

    if let Some(pw) = password {
        ctx.set_password(&name, &pw)?;
    }

    if let Some(tok) = token {
        let tok = &serde_json::from_str(&tok).inspect_err(|error| {
            error!(name, ?error, "failed to deserialize token from input");
        })?;
        ctx.set_token(&name, tok)?;
    }

    if current {
        let _ = config.current_context.insert(name.clone());
    }

    config.contexts.insert(name.clone(), ctx);

    save_config(&config)?;

    out!("context created");

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
    } = load_config()?;
    let name = match name.or(current_context.clone()) {
        Some(x) => x,
        None => {
            out!(
                "no context name given and no active context —  \
                 pass a name or set one with \"context use\""
            );

            return Err(Error::ContextSelection);
        }
    };
    if let Some(entry) = contexts.get_mut(&name) {
        let password = resolve_password(password)?;

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
        if let Some(pw) = password {
            entry.set_password(&name, &pw)?;
        }
        if let Some(tok) = token {
            let tok = &serde_json::from_str(&tok).inspect_err(|error| {
                error!(name, ?error, "failed to deserialize token from input");
            })?;
            entry.set_token(&name, tok)?;
        }

        save_config(&Config {
            current_context,
            contexts,
        })?;

        out!("context updated");

        Ok(())
    } else {
        out!(
            "context '{name}' not found —  \
             use \"context create\" to add it"
        );

        Err(Error::ContextNotFound)
    }
}

pub fn delete(yes: bool, name: String) -> Result<()> {
    let mut config = load_config()?;
    if !yes {
        if !confirm(&format!("delete context \"{name}\"?"))? {
            out!("aborted");
            return Ok(());
        }
    }

    if config.current_context.as_ref() == Some(&name) {
        config.current_context.take();
    }
    if let Some(ctx) = config.contexts.remove(&name) {
        ctx.delete_secrets()?;
    } else {
        out!(
            "context '{name}' not found —  \
             use \"context create\" to add it"
        );

        return Err(Error::ContextNotFound);
    }

    save_config(&config)?;

    out!("context deleted");

    Ok(())
}

pub fn list(format: OutputFormat) -> Result<()> {
    let config = load_config()?;

    if config.contexts.is_empty() {
        outfmt!(format, "no context configured");
        return Ok(());
    }

    match format {
        OutputFormat::Json => {
            let mut map = serde_json::Map::new();
            if let Some(cur) = &config.current_context {
                map.insert("current-context".into(), cur.clone().into());
            }
            map.insert("contexts".into(), serde_json::to_value(&config.contexts)?);
            out!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(map)).inspect_err(
                    |error| {
                        error!(%error, %format, "failed to serialize contexts");
                    }
                )?
            );
        }
        OutputFormat::Plain => {
            out!();
            for (name, ctx) in config.contexts.iter() {
                print_context(name, ctx, Some(name) == config.current_context.as_ref());
            }
            out!();
        }
    }

    Ok(())
}
