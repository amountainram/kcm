use crate::cli::{AuthorizeCommands, ClientsCommands, OutputFormat};
use cli::{Args, Commands, ContextCommands, Parser};
pub use error::{Error, Result};
use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};
use tracing::error;

mod cli;
mod client;
mod commands;
mod error;

#[macro_export]
macro_rules! out {
    () => {
        println!("\n");
    };
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! outfmt {
    ($fmt:ident, $($arg:tt)*) => {{
        if matches!($fmt, crate::cli::OutputFormat::Json) {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    }};
}

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
        ContextCommands::Show { format } => commands::context::show(format),
        ContextCommands::List { format } => commands::context::list(format),
    }
}

fn authorize_action(command: AuthorizeCommands) -> Result<()> {
    match command {
        AuthorizeCommands::Status { context, format } => {
            commands::authorize::status(context, format)
        }
        AuthorizeCommands::Login { context } => commands::authorize::login(context),
        AuthorizeCommands::Logout { context } => commands::authorize::logout(context),
    }
}

fn exclude_realms(
    format: Option<OutputFormat>,
    outer: Option<String>,
    inner: Option<String>,
) -> Result<Option<String>> {
    match (outer, inner) {
        (Some(_), Some(_)) => {
            let msg = "realm specified in multiple positions";
            if let Some(f) = format {
                outfmt!(f, "{msg}");
            } else {
                out!("{msg}");
            }
            Err(Error::TooManyArguments)
        }
        (Some(x), _) | (_, Some(x)) => Ok(Some(x)),
        _ => Ok(None),
    }
}

fn clients_action(command: ClientsCommands, cmd_realm: Option<String>) -> Result<()> {
    match command {
        ClientsCommands::List {
            page_size,
            format,
            realm,
            search,
        } => commands::clients::list(
            page_size,
            format,
            exclude_realms(Some(format), cmd_realm, realm)?,
            search,
        ),
    }
}

fn main() -> ExitCode {
    let Args { command } = Args::parse();

    (|| {
        logger_try_init().inspect_err(|error| {
            error!(%error, "failed to initialize logger");
        })?;

        let result = match command {
            Commands::Context { command } => context_action(command),
            Commands::Authorize { command } => authorize_action(command),
            Commands::Clients { command, realm } => clients_action(command, realm),
        }
        .inspect_err(|error| {
            if tracing::enabled!(tracing::Level::DEBUG) {
                error!(?error, "error on exit");
            }
        });

        let _ = io::stderr()
            .flush()
            .inspect_err(|error| error!(%error, "failed to flush stderr"));

        result
    })()
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
        .with(tracing_subscriber::fmt::layer().with_writer(io::stderr))
        .try_init()?;

    Ok(())
}
