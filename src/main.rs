use cli::{Args, Commands, ContextCommands, Parser};
pub use error::{Context, Error, Result};
use std::{env, process::ExitCode};

mod cli;
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

fn main() -> ExitCode {
    let Args { command } = Args::parse();

    if logger_try_init().is_err() {
        return ExitCode::FAILURE;
    }

    let result = match command {
        Commands::Context { command } => context_action(command),
    };

    if result.is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn logger_try_init() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    const DEFAULT_MODULE_FILTERS: &str = concat!(
        "h2=info,",
        "h2::codec::framed_write=info,",
        "hyper_util::client=info,",
        "rustls=info,",
    );

    let log_level = env::var("LOG_LEVEL").or_else(|err| {
        if matches!(err, env::VarError::NotPresent) {
            Ok(::tracing::Level::INFO.to_string())
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
