use super::{PasswordManagement, TokenAuthMethod};
use crate::commands::Sensitive;
use clap::{Subcommand, ValueEnum};
use kcm_derive::Completions;

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum BootstrapAdminPostAction {
    /// Disables the admin that is currently logged in
    /// if the new admin username is different from current
    #[default]
    #[value(name = "disable-current-admin")]
    DisableCurrentAdmin,
    /// Removes the admin that is currently logged in
    /// if the new admin username is different from current
    #[value(name = "remove-current-amdin")]
    RemoveCurrentAdmin,
    /// Do not do anything
    #[value(name = "none")]
    None,
}

#[derive(Subcommand, Completions)]
pub enum BootstrapCommands {
    /// Resets the password for the admin user,
    /// if the user does not exists it creates one
    #[command(name = "admin")]
    Admin {
        #[command(flatten)]
        secret_management: PasswordManagement,
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        #[arg(long = "then", default_value = "disable-current-admin")]
        post_action: BootstrapAdminPostAction,
    },
    #[command(name = "openid")]
    Openid {
        name: String,
        #[arg(long = "url")]
        openid_configuration_url: String,
        #[arg(long = "client-id")]
        client_id: String,
        #[arg(long = "display-name")]
        display_name: Option<String>,
        #[arg(long = "trust-email")]
        trust_email: bool,
        #[arg(long = "organization")]
        organization: Option<String>,
        #[arg(long = "vault-key")]
        vault_key: Option<String>,
        #[arg(long = "secret")]
        secret: Option<Sensitive>,
        #[arg(long = "token-method")]
        token_method: Option<TokenAuthMethod>,
        /// Working realm
        #[arg(short = 'r', long = "realm")]
        realm: Option<String>,
    },
}
