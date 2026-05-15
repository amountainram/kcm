use super::OutputFormat;
use crate::{commands, completions};
use clap::Subcommand;
use kcm_derive::Completions;

#[derive(Subcommand, Completions)]
pub enum UsersCommands {
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
        /// Username string
        #[completion(values = "complete_usernames")]
        username: String,
    },
    #[command(name = "enable", alias = "on")]
    Enable {
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Username string
        #[completion(values = "complete_usernames")]
        username: String,
    },
    #[command(name = "disable", alias = "off")]
    Disable {
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
        /// Username string
        #[completion(values = "complete_usernames")]
        username: String,
    },
}

/// Dynamic username completer — called when the user tabs on a `username` positional.
/// Fetch at most [`crate::completions::COMPLETION_PAGE_SIZE`] matching users.
/// Returning exactly that many signals the shell to display "keep typing to narrow".
fn complete_usernames(prefix: &str, words: &[String]) -> Vec<String> {
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
        let (realm, mut client) = commands::in_place(realm)?;
        client
            .users_list_hint(&realm, completions::COMPLETION_PAGE_SIZE, prefix)
            .map(|c| c.into_iter().filter_map(|c| c.username).collect())
            .ok()
    })()
    .unwrap_or_default()
}
