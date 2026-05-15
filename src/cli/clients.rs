use super::{
    ClientSecretManagement, JsonManagement, JwksManagement, KeyPairManagement, OutputFormat,
    TokenAuthMethod,
};
use clap::Subcommand;
use kcm_derive::Completions;

#[derive(Subcommand, Completions)]
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
        #[command(flatten)]
        common: JwksManagement,
        /// Confirm action
        #[arg(short = 'a', long = "all")]
        all: bool,
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
        /// Show client secret in plaintext
        #[arg(long = "show-credentials", default_value = "false")]
        show_credentials: bool,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Search string
        #[completion(values = "complete_client_ids")]
        client_id: String,
    },
    #[command(name = "create", alias = "cr")]
    Create {
        #[command(flatten)]
        common_key: Box<KeyPairManagement>,
        #[command(flatten)]
        common_secret: ClientSecretManagement,
        #[command(flatten)]
        json: JsonManagement,
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Client description
        #[arg(long = "description")]
        description: Option<String>,
        /// Authentication method
        #[arg(long = "token-auth-method", value_enum)]
        token_auth_method: Option<TokenAuthMethod>,
        /// Access token lifespan in seconds
        #[arg(long = "access-token-lifespan")]
        access_token_lifespan: Option<i64>,
        /// Client Id
        client_id: Option<String>,
        /// Activate refresh token
        #[arg(long = "use-refresh-token")]
        use_refresh_token: Option<bool>,
    },
    /// Delete a client
    #[command(name = "delete", alias = "del")]
    Delete {
        /// Confirm action
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Client ID
        #[completion(values = "complete_client_ids")]
        client_id: String,
    },
}

/// Dynamic client-id completer — called when the user tabs on a `client_id` positional.
fn complete_client_ids(prefix: &str, words: &[String]) -> Vec<String> {
    let realm = words
        .windows(2)
        .find(|w| w[0] == "--realm" || w[0] == "-r")
        .map(|w| w[1].clone())
        .or_else(|| {
            words
                .iter()
                .find_map(|w| w.strip_prefix("--realm=").map(str::to_string))
        });

    (|| {
        let (realm, mut client) = crate::commands::in_place(realm)?;
        client
            .clients_list_hint(&realm, crate::completions::COMPLETION_PAGE_SIZE, prefix)
            .map(|cs| cs.into_iter().filter_map(|c| c.client_id).collect())
            .ok()
    })()
    .unwrap_or_default()
}
