use super::{Context, OutputFormat, Printer, Sensitive, confirm, enforce_context};
use crate::{
    Error, Result,
    cli::{
        ClientSecret, ClientSecretManagement, JsonManagement, JwksManagement, KeyMaterial,
        KeyPairManagement, TokenAuthMethod, WriteOutChecks,
    },
    client::{AdminCliClient, ClientAttributes, ClientRepresentation, settings},
    out, outfmt,
};
use colored::Colorize;
use std::{
    io::{IsTerminal, stdin},
    mem,
};
use tracing::{Level, debug, enabled, error, warn};
use typed_builder::TypedBuilder;

fn coalesce_realm<'a>(ctx: &'a Context, realm: Option<&'a str>) -> Option<&'a str> {
    realm.or(ctx.working_realm.as_deref())
}

fn prepare_client(
    format: OutputFormat,
    realm: Option<String>,
    name: String,
    ctx: Context,
) -> Result<(String, AdminCliClient)> {
    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            outfmt!(
                format,
                "cannot find server-url on current context —  \
                 use \"context update --server-url <url>\""
            );

            return Err(Error::MissingArgument);
        }
    };

    let realm = match coalesce_realm(&ctx, realm.as_deref()) {
        Some(r) => r.to_string(),
        None => {
            outfmt!(
                format,
                "cannot find realm on current context —  \
                 use \"context update --working-realm <realm>\""
            );

            return Err(Error::MissingArgument);
        }
    };

    Ok((
        realm,
        AdminCliClient::builder()
            .name(name)
            .server_url(server_url)
            .admin_server_url(ctx.admin_server_url.clone())
            .context(ctx)
            .build(),
    ))
}

fn format_client_row(c: &ClientRepresentation) -> String {
    let id = c.client_id.as_deref().unwrap_or("—");
    let enabled = if c.enabled.unwrap_or_default() {
        format!("✓").green()
    } else {
        format!("✗").red()
    };
    let protocol = c.protocol.as_deref().unwrap_or("—");
    let description = match &c.description {
        Some(d) if d.len() > 40 => format!("{}...", &d[..37]),
        Some(d) => d.clone(),
        None => String::new(),
    };
    format!("  {enabled}  {id:<36} {protocol:<16} {description}")
}

fn print_clients(page: u64, page_size: u64, clients: &[ClientRepresentation]) {
    let header = format!("     {:36} {:16} DESCRIPTION", "CLIENT ID", "PROTOCOL");
    let separator = format!("  {}", "─".repeat(74));
    out!("{}", format!("\n  page {page}\n").dimmed());
    out!("{}", format!("{header}\n").dimmed());
    out!("{}", format!("{separator}\n").dimmed());
    for c in clients {
        out!("{}", format_client_row(c));
    }
    if clients.len() as u64 == page_size {
        out!(
            "{}{}{}{}{}{}",
            format!("\n  :").dimmed(),
            format!(" next page "),
            format!("|").dimmed(),
            format!(" "),
            format!("q").dimmed(),
            format!("  quit\n")
        );
    }
}

fn wait_for_keypress() -> Result<bool> {
    use crossterm::{
        event::{self, Event, KeyCode},
        terminal,
    };

    terminal::enable_raw_mode()?;
    let result = loop {
        if let Event::Key(key) = event::read()? {
            break match key.code {
                KeyCode::Char('q') | KeyCode::Esc => false,
                _ => true,
            };
        }
    };
    terminal::disable_raw_mode()?;

    Ok(result)
}

pub fn list(
    page_size: u64,
    format: OutputFormat,
    realm: Option<String>,
    search: Option<String>,
) -> Result<()> {
    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm, name, ctx)?;

    let mut offset = 0;
    let mut page = 1;
    let mut clients = vec![];

    loop {
        let next_page = client
            .clients_list(&working_realm, page_size, offset, search.as_deref(), false)
            .inspect_err(|error| {
                error!(
                    %error,
                    page_size,
                    page,
                    offset,
                    %format,
                    realm = working_realm,
                    "failed to fetch clients"
                );
            })?;
        let next_page_len = next_page.len() as u64;
        match format {
            OutputFormat::Json => {
                clients.extend(next_page);
            }
            OutputFormat::Plain => {
                print_clients(page, page_size, &next_page);
            }
        }

        if next_page_len < page_size {
            break;
        }

        if !matches!(format, OutputFormat::Json) && stdin().is_terminal() && !wait_for_keypress()? {
            break;
        }

        offset += page_size;
        page += 1;
    }

    if matches!(format, OutputFormat::Json) {
        out!(
            "{}",
            serde_json::to_string_pretty(&clients).inspect_err(|error| {
                error!(%error, "failed to serialize clients");
            })?
        )
    } else {
        out!();
    }

    Ok(())
}

macro_rules! print_or {
    ($any:ident, $printer:ident, $label:literal, $value:expr) => {
        if let Some(x) = $value {
            $printer.print_field($label, x);
            $any = true;
        }
    };
    ($any:ident, $printer:ident, $label:literal, $value:expr, $color:expr) => {
        if let Some(x) = $value {
            $printer.print_field_with_color($label, x, $color);
            $any = true;
        }
    };
}

#[derive(TypedBuilder, Default)]
pub struct DescribeOptions {
    #[builder(default)]
    jwks: JwksManagement,
    #[builder(default)]
    show_credentials: bool,
    #[builder(default)]
    all: bool,
}

pub fn describe(
    format: OutputFormat,
    realm: Option<String>,
    client_id: String,
    opts: DescribeOptions,
) -> Result<()> {
    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm, name, ctx)?;

    let item = client
        .client_describe(&working_realm, &client_id)
        .inspect_err(|error| {
            error!(
                %error,
                %format,
                realm = working_realm,
                client_id,
                "failed to fetch clients"
            );
        })?;

    if let Some(client) = item {
        let mut printer = Printer::builder().format(format).label_width(26).build();
        let ClientRepresentation {
            id,
            client_id,
            admin_url,
            attributes,
            base_url,
            client_authenticator_type,
            default_client_scopes,
            default_roles,
            description,
            direct_access_grants_enabled,
            direct_grants_only,
            enabled,
            frontchannel_logout,
            full_scope_allowed,
            implicit_flow_enabled,
            name,
            optional_client_scopes,
            origin,
            public_client,
            redirect_uris,
            root_url,
            secret,
            service_accounts_enabled,
            standard_flow_enabled,
            type_,
            web_origins,
            ..
        } = client;

        if opts.jwks.should_write() {
            let attributes_json_map = attributes
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect::<serde_json::Map<_, _>>();
            let client_attributes = serde_json::from_value::<ClientAttributes>(
                serde_json::Value::Object(attributes_json_map),
            )
            .inspect_err(|error| error!(%error, "invalid client attributes"))?;
            if let Some(jwks) = client_attributes.jwks_string {
                opts.jwks.write_out(
                    serde_json::to_string_pretty(&jwks)
                        .inspect_err(|error| error!(%error, "invalid jwks"))?,
                )?;
            }
        }

        printer.ln();

        let mut grant_types = vec![];
        if client.standard_flow_enabled.unwrap_or(false) {
            grant_types.push("Authorization Code");
        }
        if client.service_accounts_enabled.unwrap_or(false) {
            grant_types.push("Client Credentials");
        }
        if client.direct_access_grants_enabled.unwrap_or(false) {
            grant_types.push("Resource Owner Password");
        }
        if client.implicit_flow_enabled.unwrap_or(false) {
            grant_types.push("Implicit");
        }
        if grant_types.is_empty() {
            printer.print_info("[info] oauth2 grants", "[none]");
        } else {
            printer.print_info(
                "[info] oauth2 grants",
                format!("[{}]", grant_types.join(", ")).dimmed(),
            );
        }
        let mut token_auth_modes = vec![];
        if matches!(
            client_authenticator_type.as_deref(),
            Some(settings::CLIENT_AUTHENTICATOR_TYPE_SECRET)
        ) {
            token_auth_modes.push("client_secret_basic");
            token_auth_modes.push("client_secret_post");
        }
        if matches!(
            client_authenticator_type.as_deref(),
            Some(settings::CLIENT_AUTHENTICATOR_TYPE_SECRET_JWT)
        ) {
            token_auth_modes.push("client_secret_jwt");
        }
        if matches!(
            client_authenticator_type.as_deref(),
            Some(settings::CLIENT_AUTHENTICATOR_TYPE_X509)
        ) {
            token_auth_modes.push("tls_client_auth");
        }
        if matches!(
            client_authenticator_type.as_deref(),
            Some(settings::CLIENT_AUTHENTICATOR_TYPE_JWT)
        ) {
            token_auth_modes.push("private_key_jwt");
        }
        if token_auth_modes.is_empty() {
            printer.print_info("[info] token auth", "[none]");
        } else {
            printer.print_info(
                "[info] token auth",
                format!("[{}]", token_auth_modes.join(", ")).dimmed(),
            );
        }

        printer.ln();
        let mut any = false;

        print_or!(any, printer, "id", id);
        print_or!(any, printer, "clientId", client_id);
        print_or!(any, printer, "name", name);
        print_or!(any, printer, "description", description);
        print_or!(any, printer, "type", type_);
        print_or!(any, printer, "fullScopeAllowed", full_scope_allowed);
        print_or!(
            any,
            printer,
            "enabled",
            enabled,
            match enabled {
                Some(true) => colored::Color::Green,
                Some(false) | None => colored::Color::Red,
            }
        );

        if any {
            printer.ln();
        }
        any = false;

        print_or!(
            any,
            printer,
            "publicClient",
            public_client,
            match public_client {
                Some(true) => colored::Color::Magenta,
                Some(false) | None => colored::Color::Green,
            }
        );
        print_or!(
            any,
            printer,
            "clientAuthenticatorType",
            client_authenticator_type.clone()
        );
        print_or!(any, printer, "standardFlowEnabled", standard_flow_enabled);
        print_or!(any, printer, "implicitFlowEnabled", implicit_flow_enabled);
        print_or!(
            any,
            printer,
            "directAccessGrantsEnabled",
            direct_access_grants_enabled
        );
        print_or!(any, printer, "directGrantsOnly", direct_grants_only);
        print_or!(
            any,
            printer,
            "serviceAccountsEnabled",
            service_accounts_enabled
        );

        if any {
            printer.ln();
        }
        any = false;

        if matches!(
            client_authenticator_type.as_deref(),
            Some(settings::CLIENT_AUTHENTICATOR_TYPE_SECRET)
        ) {
            let secret = secret.map(|cred| {
                if !opts.show_credentials {
                    Sensitive::from(cred).to_string()
                } else {
                    cred.to_string()
                }
            });
            print_or!(
                any,
                printer,
                "secret",
                secret.as_ref().map(|s| s.to_string())
            );
        }

        if !opts.all {
            if any {
                printer.ln();
            }
            return Ok(());
        }

        print_or!(
            any,
            printer,
            "attributes",
            (!attributes.is_empty()).then_some(
                attributes
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect::<serde_json::Map<_, _>>()
            )
        );
        print_or!(
            any,
            printer,
            "defaultClientScopes",
            default_client_scopes
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into()
        );
        print_or!(
            any,
            printer,
            "optionalClientScopes",
            optional_client_scopes
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into()
        );
        print_or!(
            any,
            printer,
            "defaultRoles",
            default_roles
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into()
        );

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "adminUrl", admin_url);
        print_or!(any, printer, "rootUrl", root_url);
        print_or!(any, printer, "baseUrl", base_url);
        print_or!(
            any,
            printer,
            "redirectUris",
            redirect_uris
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into()
        );
        print_or!(any, printer, "frontchannelLogout", frontchannel_logout);
        print_or!(any, printer, "origin", origin);
        print_or!(
            any,
            printer,
            "webOrigins",
            web_origins
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into()
        );

        if any {
            printer.ln();
        }
    } else {
        outfmt!(
            format,
            "client '{client_id}' not found —  \
             use \"clients list [search]\" to search existing clients"
        );
    }

    Ok(())
}

#[derive(TypedBuilder, Default)]
pub struct CreateOptions {
    #[builder(setter(into))]
    client_id: Option<String>,
    #[builder(setter(into))]
    description: Option<String>,
    access_token_lifespan: Option<i64>,
    secret_management: ClientSecretManagement,
    key_pair_management: KeyPairManagement,
    token_auth_method: Option<TokenAuthMethod>,
    use_refresh_token: Option<bool>,
    json_management: JsonManagement,
}

enum Credentials {
    PrivateKeyJWT(KeyMaterial),
    ClientSecretJWT(ClientSecret),
    ClientSecretPost(ClientSecret),
    ClientSecretBasic(ClientSecret),
}

pub fn create(format: OutputFormat, realm: Option<String>, opts: CreateOptions) -> Result<()> {
    let json = opts.json_management.into_json()?;
    let extra = json
        .used()
        .then(|| {
            json.from_value::<ClientRepresentation>().inspect_err(
                |error| error!(%error, "failed to deserialize json as client representation"),
            )
        })
        .transpose()?;

    // <= credentials out here
    let credentials = match opts.token_auth_method {
        Some(TokenAuthMethod::PrivateKeyJWT) => {
            let unused = opts.secret_management.used();
            if !unused.is_empty() {
                warn!(
                    "unused parameter{} {}",
                    (unused.len() == 1).then_some("s").unwrap_or_default(),
                    unused.join(", ")
                );
            }

            let key_material = opts.key_pair_management.to_pair()?;
            if key_material.should_write() {
                key_material.can_write()?;
            }
            Some(Credentials::PrivateKeyJWT(key_material))
        }
        Some(TokenAuthMethod::ClientSecretJWT) => {
            let secret = opts.secret_management.to_secret()?;
            if secret.should_write() {
                secret.can_write()?;
            }
            Some(Credentials::ClientSecretJWT(secret))
        }
        Some(TokenAuthMethod::TlsClientAuth) => {
            unimplemented!()
        }
        Some(TokenAuthMethod::ClientSecretPost) => {
            let secret = opts.secret_management.to_secret()?;
            let unused = opts.key_pair_management.used();
            if !unused.is_empty() {
                warn!(
                    "unused parameter{} {}",
                    (unused.len() == 1).then_some("s").unwrap_or_default(),
                    unused.join(", ")
                );
            }
            if secret.should_write() {
                secret.can_write()?;
            }
            Some(Credentials::ClientSecretPost(secret))
        }
        Some(TokenAuthMethod::ClientSecretBasic) => {
            let secret = opts.secret_management.to_secret()?;
            let unused = opts.key_pair_management.used();
            if !unused.is_empty() {
                warn!(
                    "unused parameter{} {}",
                    (unused.len() == 1).then_some("s").unwrap_or_default(),
                    unused.join(", ")
                );
            }
            if secret.should_write() {
                secret.can_write()?;
            }
            Some(Credentials::ClientSecretBasic(secret))
        }
        None => {
            if !opts.secret_management.used().is_empty() {
                Some(Credentials::ClientSecretPost(
                    opts.secret_management.to_secret()?,
                ))
            } else if !opts.key_pair_management.used().is_empty() {
                Some(Credentials::PrivateKeyJWT(
                    opts.key_pair_management.to_pair()?,
                ))
            } else {
                None
            }
        }
    };

    let mut client_attributes = ClientAttributes {
        pkce_code_challenge_method: Some(settings::PKCE_CODE_CHALLENGE_METHOD_S256.into()),
        backchannel_logout_session_required: Some(true),
        frontchannel_logout_session_required: Some(true),
        use_refresh_tokens: opts.use_refresh_token.unwrap_or(false).into(),
        use_refresh_token_for_client_credentials_grant: Some(false),
        access_token_lifespan: opts.access_token_lifespan,
        ..Default::default()
    };
    let mut client_repr = ClientRepresentation {
        client_id: opts
            .client_id
            .or_else(|| Some(uuid::Uuid::now_v7().to_string())),
        description: opts.description,
        implicit_flow_enabled: Some(false),
        direct_access_grants_enabled: Some(false),
        direct_grants_only: Some(false),
        enabled: Some(true),
        full_scope_allowed: Some(false),
        default_client_scopes: vec![],
        optional_client_scopes: vec![],
        ..Default::default()
    };

    const DEFAULT_TOKEN_ENDPOINT_AUTH_SIGNING_MAX_EXP: i64 = 300;
    if let Some(method) = &credentials {
        match method {
            Credentials::ClientSecretBasic(_) | Credentials::ClientSecretPost(_) => {
                let _ = client_repr.client_authenticator_type =
                    Some(settings::CLIENT_AUTHENTICATOR_TYPE_SECRET.into());
            }
            Credentials::ClientSecretJWT(_) => {
                let _ = client_repr.client_authenticator_type =
                    Some(settings::CLIENT_AUTHENTICATOR_TYPE_SECRET_JWT.into());
                let _ = client_attributes.token_endpoint_auth_signing_max_exp =
                    Some(DEFAULT_TOKEN_ENDPOINT_AUTH_SIGNING_MAX_EXP.to_string());
            }
            Credentials::PrivateKeyJWT(_) => {
                let _ = client_repr.client_authenticator_type =
                    Some(settings::CLIENT_AUTHENTICATOR_TYPE_JWT.into());
                let _ = client_attributes.token_endpoint_auth_signing_max_exp =
                    Some(DEFAULT_TOKEN_ENDPOINT_AUTH_SIGNING_MAX_EXP.to_string());
            } // TokenAuthMethod::TlsClientAuth => {
              //     let _ = client_repr.client_authenticator_type =
              //         Some(settings::CLIENT_AUTHENTICATOR_TYPE_X509.into());
              // }
        }
    } else {
        let _ = client_repr.public_client.insert(true);
    }

    if let Some(creds) = &credentials {
        match creds {
            Credentials::ClientSecretBasic(ClientSecret { secret, .. })
            | Credentials::ClientSecretPost(ClientSecret { secret, .. })
            | Credentials::ClientSecretJWT(ClientSecret { secret, .. }) => {
                let _ = client_attributes.use_jwks_string.insert(false);
                let _ = client_attributes.use_jwks_url.insert(false);
                let _ = client_repr.secret.insert(secret.read().to_string());
            }
            Credentials::PrivateKeyJWT(KeyMaterial::PublicKey { pem }) => {
                let _ = client_attributes.use_jwks_string.insert(false);
                let _ = client_attributes.use_jwks_url.insert(false);
                let _ = client_attributes
                    .jwt_credential_public_key
                    .insert(pem.clone());
            }
            Credentials::PrivateKeyJWT(KeyMaterial::Jwks { jwks, .. })
            | Credentials::PrivateKeyJWT(KeyMaterial::PrivateKeyAndJwks { jwks, .. }) => {
                let _ = client_attributes.use_jwks_string.insert(true);
                let _ = client_attributes.use_jwks_url.insert(false);
                let _ = client_attributes.jwks_string.insert(jwks.clone());
            }
            Credentials::PrivateKeyJWT(KeyMaterial::JwksUrl { url }) => {
                let _ = client_attributes.use_jwks_string.insert(false);
                let _ = client_attributes.use_jwks_url.insert(true);
                let _ = client_attributes.jwks_url.insert(url.clone());
            }
        }
    }

    let _ = mem::replace(&mut client_repr.attributes, client_attributes.into());
    if let Some(extra) = extra {
        client_repr.extend(extra, json.mode());
    }

    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm.clone(), name, ctx)?;

    if enabled!(Level::DEBUG) {
        debug!(
            realm = working_realm,
            client_id = client_repr.client_id,
            repr = ?client_repr, "creating client"
        );
    }
    let client_id = client
        .client_create(&working_realm, client_repr)
        .inspect_err(|error| {
            error!(
                %error,
                %format,
                realm = working_realm,
                "failed to create client"
            );
        })?;

    if let Some(credentials) = credentials {
        match credentials {
            Credentials::PrivateKeyJWT(key_material) => {
                key_material.write_out()?;
            }
            Credentials::ClientSecretJWT(client_secret)
            | Credentials::ClientSecretPost(client_secret)
            | Credentials::ClientSecretBasic(client_secret) => {
                client_secret.write_out()?;
            }
        }
    }

    if let Some(client_id) = client_id {
        describe(format, realm, client_id, Default::default())?;
    } else {
        out!("resource client created");
    }

    Ok(())
}

pub fn delete(yes: bool, realm: Option<String>, client_id: String) -> Result<()> {
    let format = Default::default();
    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm.clone(), name, ctx)?;

    if !yes {
        if !confirm(&format!("delete client \"{client_id}\"?"))? {
            out!("aborted");
            return Ok(());
        }
    }

    client
        .client_delete(&working_realm, client_id)
        .inspect_err(|error| {
            error!(
                %error,
                %format,
                realm = working_realm,
                "failed to create client"
            );
        })?;

    out!("client deleted");

    Ok(())
}
