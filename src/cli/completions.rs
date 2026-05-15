use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
pub enum ShellKind {
    #[value(name = "bash")]
    Bash,
    #[value(name = "zsh")]
    Zsh,
}

/// Completion usage:
///
/// - `kcm completions script bash` — print shell script
/// - `kcm completions install` — auto-install
/// - `kcm completions complete context use` — dynamic completion (called by the shell script)
#[derive(Subcommand)]
pub enum CompletionsCommands {
    /// Complete command
    Complete {
        /// Current partial word being typed (used to decide whether to emit subcommands or flags)
        #[arg(long = "cur", default_value = "", allow_hyphen_values = true)]
        cur: String,
        /// Previously completed words on the command line
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
    /// Print completion script to stdout
    Script {
        /// The shell type
        shell: Option<ShellKind>,
    },
    /// Install completions for the current shell
    Install,
}
