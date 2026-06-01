use super::OutputFormat;
use clap::Subcommand;
use kcm_derive::Completions;

#[derive(Subcommand, Completions)]
pub enum ContextCommands {
    /// Create a new context
    #[command(name = "create", alias = "cr")]
    Create {
        /// Context name
        name: String,
        /// Alternative public client for authorization code flow
        #[arg(long = "client-id")]
        client_id: Option<String>,
        /// Set to current upon creation
        #[arg(long = "current")]
        current: bool,
        /// Keycloak server base URL
        #[arg(long = "server-url")]
        server_url: Option<String>,
        /// Keycloak server base URL
        #[arg(long = "admin-server-url")]
        admin_server_url: Option<String>,
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
    #[command(name = "update", alias = "up")]
    Update {
        /// Context name (defaults to current)
        #[completion(values = "complete_context_name")]
        name: Option<String>,
        /// Alternative public client for authorization code flow
        #[arg(long = "client-id")]
        client_id: Option<String>,
        /// Keycloak server base URL
        #[arg(long = "server-url")]
        server_url: Option<String>,
        /// Keycloak server base URL
        #[arg(long = "admin-server-url")]
        admin_server_url: Option<String>,
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
    #[command(name = "unset")]
    Unset {
        /// Context name (defaults to current)
        #[completion(values = "complete_context_name")]
        name: Option<String>,
        /// Alternative public client for authorization code flow
        #[arg(long = "client-id", default_value_t = false)]
        client_id: bool,
        /// Keycloak server base URL
        #[arg(long = "server-url", default_value_t = false)]
        server_url: bool,
        /// Keycloak server base URL
        #[arg(long = "admin-server-url", default_value_t = false)]
        admin_server_url: bool,
        /// Default working realm
        #[arg(long = "working-realm", default_value_t = false)]
        working_realm: bool,
        /// Username
        #[arg(short = 'u', long = "username", default_value_t = false)]
        username: bool,
        /// Password
        #[arg(short = 'p', long = "password", default_value_t = false)]
        password: bool,
        /// Access token
        #[arg(long = "token", default_value_t = false)]
        token: bool,
    },
    /// Set the active context
    #[command(name = "use")]
    Use {
        /// Context name (interactive if omitted)
        #[completion(values = "complete_context_name")]
        name: Option<String>,
    },
    /// Delete a context
    #[command(name = "delete", alias = "del")]
    Delete {
        /// Confirm action
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Context name
        #[completion(values = "complete_context_name")]
        name: String,
    },
    /// List all contexts
    #[command(name = "list", alias = "ls", alias = "ps")]
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

fn complete_context_name(prefix: &str, _words: &[String]) -> Vec<String> {
    crate::commands::context_names()
        .into_iter()
        .filter(|n| n.starts_with(prefix))
        .collect()
}
