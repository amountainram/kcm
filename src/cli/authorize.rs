use clap::Subcommand;
use kcm_derive::Completions;

#[derive(Subcommand, Completions)]
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
