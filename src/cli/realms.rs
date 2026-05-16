use super::OutputFormat;
use crate::{commands, completions};
use clap::Subcommand;
use kcm_derive::Completions;

#[derive(Subcommand, Completions)]
pub enum RealmsCommands {
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
        /// Search string
        search: Option<String>,
    },
    #[command(name = "describe", alias = "desc", alias = "d")]
    Describe {
        /// Output format
        #[arg(long = "format", default_value = "plain")]
        format: OutputFormat,
        /// Username string
        #[completion(values = "complete_realms")]
        realm: String,
    },
}

/// Dynamic realm completer — called when the user tabs on a `realm` positional.
/// Fetch at most [`crate::completions::COMPLETION_PAGE_SIZE`] matching users.
/// Returning exactly that many signals the shell to display "keep typing to narrow".
fn complete_realms(prefix: &str, _words: &[String]) -> Vec<String> {
    (|| {
        let (_, mut client) = commands::in_place("master".to_string().into())?;
        client
            .realms_list_hint(completions::COMPLETION_PAGE_SIZE, prefix)
            .map(|c| c.into_iter().filter_map(|c| c.realm).collect())
            .ok()
    })()
    .unwrap_or_default()
}
