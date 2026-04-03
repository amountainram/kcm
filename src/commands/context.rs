use super::{Config, Context, current_context, load_config, save_config};
use crate::{Context as _, Error, Result};
use std::{
    io::{self, IsTerminal, Write},
    process::{Command, Stdio},
};
use tracing::{error, info};

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
