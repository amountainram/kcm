pub use clap::Parser;
use clap::{Subcommand, ValueEnum};
use std::fmt;

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Plain,
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "plain",
                Self::Json => "json",
            }
        )
    }
}

#[derive(Subcommand)]
pub enum ContextCommands {
    /// Create a new context
    #[command(name = "create")]
    Create {
        /// Context name
        name: String,
        /// Set to current upon creation
        #[arg(long = "current")]
        current: bool,
        /// Keycloak server base URL
        #[arg(long = "server-url")]
        server_url: Option<String>,
        /// Authorization realm
        #[arg(long = "auth-realm")]
        realm: Option<String>,
        /// Default working realm
        #[arg(long = "working-realm")]
        working_realm: Option<String>,
        /// Username
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        /// Password
        #[arg(
            short = 'p',
            long = "password",
            num_args = 0..=1,
            default_missing_value = ""
        )]
        password: Option<String>,
        /// Access token
        #[arg(long = "token")]
        token: Option<String>,
    },
    /// Update an existing context
    #[command(name = "update")]
    Update {
        /// Context name (defaults to current)
        name: Option<String>,
        /// Set to current
        #[arg(long = "current")]
        current: bool,
        /// Keycloak server base URL
        #[arg(long = "server-url")]
        server_url: Option<String>,
        /// Authorization realm
        #[arg(long = "auth-realm")]
        realm: Option<String>,
        /// Default working realm
        #[arg(long = "working-realm")]
        working_realm: Option<String>,
        /// Username
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        /// Password
        #[arg(
            short = 'p',
            long = "password",
            num_args = 0..=1,
            default_missing_value = ""
        )]
        password: Option<String>,
        /// Access token
        #[arg(long = "token")]
        token: Option<String>,
    },
    /// Set the active context
    #[command(name = "use")]
    Use {
        /// Context name (interactive if omitted)
        name: Option<String>,
    },
    /// Delete a context
    #[command(name = "delete")]
    Delete {
        /// Confirm action
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Context name
        name: String,
    },
    /// List all contexts
    #[command(name = "list")]
    List {
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
    },
    /// Show the active context
    #[command(name = "show")]
    Show {
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
    },
}

#[derive(Subcommand)]
pub enum AuthorizeCommands {
    #[command(name = "login")]
    Login {
        /// Name of the context
        context: Option<String>,
    },
    #[command(name = "logout")]
    Logout {
        /// Name of the context
        context: Option<String>,
    },
    #[command(name = "status")]
    Status {
        /// Name of the context
        context: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ClientsCommands {
    #[command(name = "list", alias = "ls", alias = "ps")]
    List {
        /// Page size for the returned list - format json
        /// overrides this argument
        #[arg(
            short = 'p',
            long = "page-size",
            default_value = "10",
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        page_size: u64,
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Search string
        search: Option<String>,
    },
    #[command(name = "describe", alias = "desc", alias = "d")]
    Describe {
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Search string
        client_id: String,
    },
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage CLI contexts
    #[command(name = "context", alias = "ctx")]
    Context {
        #[command(subcommand)]
        command: ContextCommands,
    },
    /// Manage CLI contexts
    #[command(name = "authorize", alias = "auth")]
    Authorize {
        #[command(subcommand)]
        command: AuthorizeCommands,
    },
    /// Manage realm clients
    #[command(name = "clients", alias = "c")]
    Clients {
        #[command(subcommand)]
        command: ClientsCommands,
        /// Login realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
    },
}

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}
