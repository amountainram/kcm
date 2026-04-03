use cli::{Args, Commands, ContextCommands, Parser};
pub use error::{Context, Error, Result};
use std::{env, process::ExitCode};

use crate::cli::AuthorizeCommands;

mod cli;
mod client;
mod commands;
mod error;

fn context_action(command: ContextCommands) -> Result<()> {
    match command {
        ContextCommands::Create {
            name,
            current,
            server_url,
            realm,
            username,
            password,
            token,
        } => commands::context::create(name, current, server_url, realm, username, password, token),
        ContextCommands::Update {
            name,
            current,
            server_url,
            realm,
            username,
            password,
            token,
        } => commands::context::update(name, current, server_url, realm, username, password, token),
        ContextCommands::Delete { yes, name } => commands::context::delete(yes, name),
        ContextCommands::Use { name } => commands::context::r#use(name),
        ContextCommands::Show => commands::context::show(),
        ContextCommands::List => commands::context::list(),
    }
}

fn authorize_action(command: AuthorizeCommands) -> Result<()> {
    match command {
        AuthorizeCommands::Status { context } => commands::authorize::status(context),
        AuthorizeCommands::Login { context } => commands::authorize::login(context),
        _ => {
            todo!()
        }
    }
}

fn main() -> ExitCode {
    let Args { command } = Args::parse();

    if logger_try_init().is_err() {
        return ExitCode::FAILURE;
    }

    let result = match command {
        Commands::Context { command } => context_action(command),
        Commands::Authorize { command } => authorize_action(command),
    }
    .inspect_err(|error| {
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::error!(?error, "error on exit");
        }
    });

    result
        .is_ok()
        .then_some(ExitCode::SUCCESS)
        .unwrap_or(ExitCode::FAILURE)
}

fn logger_try_init() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    const DEFAULT_MODULE_FILTERS: &str = concat!(
        "h2=info,",
        "h2::codec::framed_write=info,",
        "hyper_util::client=info,",
        "rustls=info,",
    );

    let log_level = env::var("LOG_LEVEL")
        .map(|l| l.trim().to_lowercase())
        .or_else(|err| {
            if matches!(err, env::VarError::NotPresent) {
                Ok(tracing::Level::INFO.to_string())
            } else {
                Err(err)
            }
        })?;

    // this is the only place where RUST_LOG variable is set, since it did not exist before
    // therefore it should be safe to read the variable from a multi-thread environment
    unsafe {
        // PANIC: the current usage of set_var does not panic according to its definition
        // (key is not empty, contain a NUL or `=` char, nor value contains the NUL char)
        env::set_var(
            "RUST_LOG",
            format!(
                "{bin_name}={log_level},{DEFAULT_MODULE_FILTERS}{log_level}",
                bin_name = env!("CARGO_BIN_NAME"),
            ),
        )
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()?)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .with_context(|| "failed to initialize logger")?;

    Ok(())
}
