pub use clap::Parser;
use clap::Subcommand;

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
        /// Default realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
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
        /// Default realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
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
    List,
    /// Show the active context
    #[command(name = "show")]
    Show,
}

#[derive(Subcommand)]
pub enum AuthorizeCommands {
    #[command(name = "login")]
    Login { context: Option<String> },
    #[command(name = "logout")]
    Logout { context: Option<String> },
    #[command(name = "status")]
    Status { context: Option<String> },
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
}

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}
