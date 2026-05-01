use crate::cli::{
    AuthorizeCommands, BootstrapCommands, ClientsCommands, OutputFormat, UsersCommands,
};
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
            client_id,
            current,
            server_url,
            admin_server_url,
            realm,
            working_realm,
            username,
            password,
            token,
        } => commands::context::create(
            name,
            current,
            server_url,
            admin_server_url,
            realm,
            working_realm,
            username,
            password,
            token,
            client_id,
        ),
        ContextCommands::Update {
            name,
            server_url,
            admin_server_url,
            realm,
            working_realm,
            username,
            password,
            token,
            client_id,
        } => commands::context::update(
            name,
            server_url,
            admin_server_url,
            realm,
            working_realm,
            username,
            password,
            token,
            client_id,
        ),
        ContextCommands::Unset {
            name,
            server_url,
            admin_server_url,
            working_realm,
            username,
            password,
            token,
            client_id,
        } => commands::context::unset(
            name,
            server_url,
            admin_server_url,
            working_realm,
            username,
            password,
            token,
            client_id,
        ),
        ContextCommands::Delete { yes, name } => commands::context::delete(yes, name),
        ContextCommands::Use { name } => commands::context::r#use(name),
        ContextCommands::Show { format } => commands::context::show(format),
        ContextCommands::List { format } => commands::context::list(format),
    }
}

fn authorize_action(command: AuthorizeCommands) -> Result<()> {
    match command {
        AuthorizeCommands::Status { context } => commands::authorize::status(context),
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
        ClientsCommands::Describe {
            common,
            format,
            show_credentials,
            realm,
            client_id,
            all,
        } => commands::clients::describe(
            format,
            exclude_realms(Some(format), cmd_realm, realm)?,
            client_id,
            commands::clients::DescribeOptions::builder()
                .show_credentials(show_credentials)
                .jwks(common)
                .all(all)
                .build(),
        ),
        ClientsCommands::Create {
            common_key,
            common_secret,
            json,
            format,
            realm,
            client_id,
            description,
            token_auth_method,
            access_token_lifespan,
            use_refresh_token,
        } => {
            let opts = commands::clients::CreateOptions::builder()
                .client_id(client_id)
                .description(description)
                .access_token_lifespan(access_token_lifespan)
                .secret_management(common_secret)
                .key_pair_management(common_key)
                .token_auth_method(token_auth_method)
                .use_refresh_token(use_refresh_token)
                .json_management(json)
                .build();
            commands::clients::create(format, realm, opts)
        }
        ClientsCommands::Delete {
            yes,
            realm,
            client_id,
        } => commands::clients::delete(yes, realm, client_id),
    }
}

fn bootstrap_action(command: BootstrapCommands, cmd_realm: Option<String>) -> Result<()> {
    match command {
        BootstrapCommands::Admin {
            secret_management,
            username,
            post_action,
        } => {
            let opts = commands::bootstrap::BootstrapAdminOptions::builder()
                .username(username)
                .secret_management(secret_management)
                .post_action(post_action)
                .build();
            commands::bootstrap::admin(opts)
        }
        BootstrapCommands::Openid {
            name,
            client_id,
            openid_configuration_url,
            display_name,
            trust_email,
            organization,
            vault_key,
            secret,
            token_method,
            realm,
        } => {
            let opts = commands::bootstrap::BootstrapOpenidFederationOptions::builder()
                .alias(name)
                .client_id(client_id)
                .display_name(display_name)
                .openid_configuration_url(openid_configuration_url)
                .organization(organization)
                .secret(secret)
                .token_method(token_method)
                .trust_email(trust_email)
                .vault_key(vault_key)
                .build();
            commands::bootstrap::openid_federation(exclude_realms(None, cmd_realm, realm)?, opts)
        }
    }
}

fn users_action(command: UsersCommands, cmd_realm: Option<String>) -> Result<()> {
    match command {
        UsersCommands::List {
            page_size,
            format,
            realm,
            search,
        } => commands::users::list(page_size, format, realm, search),
        UsersCommands::Describe {
            format,
            realm,
            username,
        } => commands::users::get(
            format,
            exclude_realms(Some(format), cmd_realm, realm)?,
            username,
        ),
    }
}

fn main() -> ExitCode {
    let Args { command } = Args::parse();

    (|| {
        try_init().inspect_err(|error| {
            error!(%error, "failed to initialize");
        })?;

        let result = match command {
            Commands::Bootstrap { command, realm } => bootstrap_action(command, realm),
            Commands::Context { command } => context_action(command),
            Commands::Authorize { command } => authorize_action(command),
            Commands::Clients { command, realm } => clients_action(command, realm),
            Commands::Users { command, realm } => users_action(command, realm),
        }
        .inspect_err(|error| {
            match error {
                Error::Conflict => {
                    out!(
                        "conflict while creating the resource —  \
                         resource already exists"
                    );
                }
                Error::NotFound => {
                    out!(
                        "failed to execute operation —  \
                         resource does not exist"
                    );
                }
                Error::ContextAlreadyExists => {
                    out!(
                        "context already exists —  \
                         use \"context update\" to modify it"
                    );
                }
                Error::ContextNameRequired => {
                    out!(
                        "context name required (fzf not \
                         available for interactive selection)",
                    );
                }
                Error::ContextNotFound => {
                    out!(
                        "context not found —  \
                         create one with \"context create\""
                    );
                }
                Error::ContextSelection => {
                    out!(
                        "no context name given and no active context —  \
                         pass a name or set one with \"context use\""
                    );
                }
                Error::ContextMissingUsername => {
                    out!(
                        "cannot find username on current context —  \
                         use \"context update --username <username>\""
                    );
                }
                Error::ContextMissingPassword => {
                    out!(
                        "cannot find password on current context —  \
                         use \"context update --password [password]\""
                    );
                }
                Error::ContextMissingServerUrl => {
                    out!(
                        "cannot find server-url on current context —  \
                         use \"context update --server-url <url>\""
                    );
                }
                Error::MustLogin => {
                    out!(
                        "no valid token found on current context —  \
                         use \"authorize login\" to obtain one or to refresh"
                    );
                }
                Error::JwtMissingKid | Error::JwksMissingKid | Error::JwtDecodingKey => {
                    out!(
                        "invalid authorization status —  \
                         use \"authorize login\""
                    );
                }
                _ => {}
            }

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

fn try_init() -> Result<()> {
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

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| Error::msg("failed to install default crypto provider"))?;

    keystore::use_native_store()?;

    Ok(())
}

mod keystore {
    use super::Result;

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    fn use_zbus_secret_service_store() -> Result<()> {
        use zbus_secret_service_keyring_store::Store;
        keyring_core::set_default_store(Store::new()?);
        Ok(())
    }

    pub fn use_native_store() -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
        use_zbus_secret_service_store()?;

        Ok(())
    }
}
