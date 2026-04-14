use super::{Context, OutputFormat, Printer, enforce_context};
use crate::{
    Error, Result,
    cli::JwksManagement,
    client::{AdminCliClient, ClientAttributes, ClientRepresentation},
    commands::Sensitive,
    out, outfmt,
};
use colored::Colorize;
use std::io::{IsTerminal, stdin};
use tracing::error;
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

#[derive(TypedBuilder)]
pub struct DescribeOptions {
    jwks: JwksManagement,
    show_credentials: bool,
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
        if matches!(client_authenticator_type.as_deref(), Some("client-secret")) {
            token_auth_modes.push("client_secret_basic");
            token_auth_modes.push("client_secret_post");
        }
        if matches!(
            client_authenticator_type.as_deref(),
            Some("client-secret-jwt")
        ) {
            token_auth_modes.push("client_secret_jwt");
        }
        if matches!(client_authenticator_type.as_deref(), Some("client-x509")) {
            token_auth_modes.push("tls_client_auth");
        }
        if matches!(client_authenticator_type.as_deref(), Some("client-jwt")) {
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
            client_authenticator_type
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
