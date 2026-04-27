use super::{Sensitive, enforce_context, prepare_client};
use crate::{
    Error, Result,
    cli::{BootstrapAdminPostAction, PasswordManagement, TokenAuthMethod, WriteOutChecks},
    client::{
        CredentialRepresentation, IdentityProviderConfig, IdentityProviderRepresentation,
        UserAttributes, UserRepresentation, fetch_openid_configuration, settings,
    },
    out,
};
use tracing::{error, warn};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder, Default)]
pub struct BootstrapAdminOptions {
    username: Option<String>,
    secret_management: PasswordManagement,
    post_action: BootstrapAdminPostAction,
}

fn generate_password() -> String {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use rand::{TryRng, rngs::SysRng};

    let mut bytes = vec![0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub fn admin(opts: BootstrapAdminOptions) -> Result<()> {
    let password_out = opts.secret_management.to_password()?;
    let username = opts.username.unwrap_or("admin".to_string());
    let format = Default::default();
    let (name, ctx) = enforce_context(format)?;
    let ctx_username = match &ctx.username {
        Some(s) => s.clone(),
        None => {
            out!(
                "cannot find username on current context —  \
                 use \"context update --username <username>\""
            );

            return Err(Error::MissingArgument);
        }
    };

    let (working_realm, mut client) = prepare_client(format, None, name, ctx)?;

    password_out.can_write()?;

    let password = Sensitive::from(generate_password());

    if ctx_username != username {
        let attributes = UserAttributes {
            is_temporary_admin: vec!["true".to_string()].into(),
            ..Default::default()
        };
        let user = UserRepresentation {
            enabled: true.into(),
            username: username.clone().into(),
            attributes: attributes.into(),
            email_verified: Some(true),
            credentials: vec![CredentialRepresentation {
                type_: Some(settings::CREDENTIALS_PASSWORD.into()),
                value: Some(password.read().to_string()),
                temporary: Some(false),
                ..Default::default()
            }],
            ..Default::default()
        };
        client
            .user_create(settings::MASTER_REALM, user)
            .inspect_err(|error| {
                error!(
                    %error,
                    realm = working_realm,
                    "failed to create user"
                );
            })?;

        password_out.write_out(password.read())?;

        let user = client
            .user_describe(settings::MASTER_REALM, &username)
            .inspect_err(|error| error!(%error, "failed to look up created user"))?
            .ok_or(Error::NotFound)?;
        let user_id = user.id.ok_or(Error::NotFound)?;

        let admin_role = client
            .role_get(settings::MASTER_REALM, settings::ROLE_ADMIN)
            .inspect_err(|error| error!(%error, "failed to fetch admin role"))?;

        client
            .user_assign_realm_roles(settings::MASTER_REALM, &user_id, vec![admin_role])
            .inspect_err(|error| error!(%error, "failed to assign admin role"))?;

        out!(
            "created new user '{username}' with '{}' role",
            settings::ROLE_ADMIN
        );

        match opts.post_action {
            BootstrapAdminPostAction::DisableCurrentAdmin => {
                client
                    .user_set_enabled(&working_realm, &ctx_username, false)
                    .inspect_err(
                        |error| error!(%error, username = %ctx_username, "failed to disable user"),
                    )?;

                out!("admin user '{ctx_username}' is now disabled");
            }
            BootstrapAdminPostAction::RemoveCurrentAdmin => {
                // remove admin
            }
            BootstrapAdminPostAction::None => {}
        }
    } else {
        unimplemented!()
    }

    Ok(())
}

#[derive(TypedBuilder, Default)]
pub struct BootstrapOpenidFederationOptions {
    alias: String,
    client_id: String,
    openid_configuration_url: String,
    display_name: Option<String>,
    trust_email: bool,
    organization: Option<String>,
    vault_key: Option<String>,
    secret: Option<Sensitive>,
    token_method: Option<TokenAuthMethod>,
}

pub fn openid_federation(
    realm: Option<String>,
    opts: BootstrapOpenidFederationOptions,
) -> Result<()> {
    let token_method = opts.token_method.unwrap_or(TokenAuthMethod::PrivateKeyJWT);
    let client_secret = if matches!(token_method, TokenAuthMethod::PrivateKeyJWT) {
        if opts.secret.is_some() {
            warn!("unused parameter --secret");
        }
        if opts.vault_key.is_some() {
            warn!("unused parameter --vault-key");
        }

        None
    } else {
        let secret = match (opts.secret, opts.vault_key) {
            (secret, Some(vault_key)) => {
                if secret.is_some() {
                    warn!("unused parameter --secret");
                }

                Sensitive::from(format!("${{vault.{vault_key}}}"))
            }
            (Some(client_secret), None) => client_secret,
            (None, None) => {
                out!(
                    "a client secret must be selected - \
                     missing either --secret or --vault-key arguments"
                );

                return Err(Error::MissingArgument);
            }
        };

        Some(secret)
    };

    let openid_configuration = fetch_openid_configuration(&opts.openid_configuration_url)?;
    let config = IdentityProviderConfig {
        authorization_url: Some(openid_configuration.authorization_endpoint),
        token_url: Some(openid_configuration.token_endpoint),
        user_info_url: openid_configuration.userinfo_endpoint,
        logout_url: openid_configuration.end_session_endpoint,
        token_introspection_url: openid_configuration.introspection_endpoint,
        jwks_url: Some(openid_configuration.jwks_uri),
        use_jwks_url: Some(true),
        validate_signature: Some(true),
        client_auth_method: token_method.to_string().into(),
        issuer: Some(openid_configuration.issuer),
        client_secret: client_secret.map(|s| s.read().to_string()),
        client_id: Some(opts.client_id),
        pkce_enabled: Some(
            openid_configuration
                .code_challenge_methods_supported
                .is_some(),
        ),
        pkce_method: openid_configuration
            .code_challenge_methods_supported
            .and_then(|methods| {
                let cc = settings::PKCE_CODE_CHALLENGE_METHOD_S256.to_string();
                if methods.contains(&cc) {
                    Some(cc)
                } else {
                    methods.into_iter().next()
                }
            }),
        ..Default::default()
    };
    let idp = IdentityProviderRepresentation {
        provider_id: Some(settings::IDENTITY_PROVIDER_OIDC.to_string()),
        enabled: Some(true),
        display_name: opts.display_name.unwrap_or(opts.alias.clone()).into(),
        alias: Some(opts.alias),
        trust_email: Some(opts.trust_email),
        authenticate_by_default: Some(true),
        link_only: Some(false),
        organization_id: opts.organization,
        store_token: Some(false),
        types: vec![settings::IDENTITY_PROVIDER_TYPE_USER_AUTHENTICATION.to_string()],
        config: config.into(),
        ..Default::default()
    };

    let format = Default::default();
    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm, name, ctx)?;
    client
        .identity_provider_create(&working_realm, idp)
        .inspect_err(|error| {
            error!(
                %error,
                realm = working_realm,
                "failed to create identity provider"
            );
        })?;

    out!("identity provider created");

    Ok(())
}
