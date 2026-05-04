use super::{OutputFormat, Printer, enforce_context, prepare_client};
use crate::{Result, client::UserRepresentation, out, outfmt};
use colored::Colorize;
use std::io::{IsTerminal, stdin};
use tracing::error;

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

fn format_user_row(u: &UserRepresentation) -> String {
    let username = u.username.as_deref().unwrap_or("—");
    let enabled = if u.enabled.unwrap_or_default() {
        "✓".to_string().green()
    } else {
        "✗".to_string().red()
    };
    let email = u.email.as_deref().unwrap_or("—");
    let name = match (&u.first_name, &u.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.clone(),
        (None, Some(l)) => l.clone(),
        (None, None) => String::new(),
    };
    format!("  {enabled}  {username:<32} {email:<32} {name}")
}

fn print_users(page: u64, page_size: u64, users: &[UserRepresentation]) {
    let header = format!("     {:32} {:32} NAME", "USERNAME", "EMAIL");
    let separator = format!("  {}", "─".repeat(80));
    out!("{}", format!("\n  page {page}\n").dimmed());
    out!("{}", format!("{header}\n").dimmed());
    out!("{}", format!("{separator}\n").dimmed());
    for u in users {
        out!("{}", format_user_row(u));
    }
    if users.len() as u64 == page_size {
        out!(
            "{}{}{}{}{}{}",
            "\n  :".to_string().dimmed(),
            format!(" next page "),
            "|".to_string().dimmed(),
            format!(" "),
            "q".to_string().dimmed(),
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
            break !matches!(key.code, KeyCode::Char('q') | KeyCode::Esc);
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
    let mut users = vec![];

    loop {
        let next_page = client
            .users_list(&working_realm, page_size, offset, search.as_deref(), false)
            .inspect_err(|error| {
                error!(
                    %error,
                    page_size,
                    page,
                    offset,
                    %format,
                    realm = working_realm,
                    "failed to fetch users"
                );
            })?;
        let next_page_len = next_page.len() as u64;
        match format {
            OutputFormat::Json => {
                users.extend(next_page);
            }
            OutputFormat::Plain => {
                print_users(page, page_size, &next_page);
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
            serde_json::to_string_pretty(&users).inspect_err(|error| {
                error!(%error, "failed to serialize users");
            })?
        )
    } else {
        out!();
    }

    Ok(())
}

pub fn get(format: OutputFormat, realm: Option<String>, username: String) -> Result<()> {
    let (name, ctx) = enforce_context(format)?;
    let (working_realm, mut client) = prepare_client(format, realm, name, ctx)?;

    let item = client
        .user_describe(&working_realm, &username)
        .inspect_err(|error| {
            error!(
                %error,
                %format,
                realm = working_realm,
                username,
                "failed to fetch user"
            );
        })?;

    if let Some(user) = item {
        let mut printer = Printer::builder().format(format).label_width(26).build();
        let UserRepresentation {
            id,
            username,
            first_name,
            last_name,
            email,
            email_verified,
            enabled,
            created_timestamp,
            required_actions,
            realm_roles,
            client_roles: _,
            groups,
            federation_link,
            federated_identities,
            service_account_client_id,
            attributes,
            totp,
            ..
        } = user;

        printer.ln();
        let mut any = false;

        print_or!(any, printer, "id", id);
        print_or!(any, printer, "username", username);
        print_or!(any, printer, "firstName", first_name);
        print_or!(any, printer, "lastName", last_name);
        print_or!(any, printer, "email", email);
        print_or!(any, printer, "emailVerified", email_verified);
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
        print_or!(any, printer, "createdTimestamp", created_timestamp);

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "totp", totp);
        print_or!(any, printer, "federationLink", federation_link);
        print_or!(
            any,
            printer,
            "serviceAccountClientId",
            service_account_client_id
        );

        if !federated_identities.is_empty() {
            for fi in &federated_identities {
                let provider = fi.identity_provider.as_deref().unwrap_or("—");
                let sub = fi.user_id.as_deref().unwrap_or("—");
                printer.print_field(format!("federatedIdentity.{provider}"), sub);
            }
            any = true;
        }

        if !required_actions.is_empty() {
            printer.print_field(
                "requiredActions",
                required_actions
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>(),
            );
            any = true;
        }

        if !realm_roles.is_empty() {
            printer.print_field(
                "realmRoles",
                realm_roles
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>(),
            );
            any = true;
        }

        if !groups.is_empty() {
            printer.print_field(
                "groups",
                groups
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>(),
            );
            any = true;
        }

        if !attributes.is_empty() {
            printer.print_field(
                "attributes",
                attributes
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            serde_json::Value::Array(
                                v.into_iter().map(serde_json::Value::String).collect(),
                            ),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>(),
            );
            any = true;
        }

        if any {
            printer.ln();
        }
    } else {
        outfmt!(
            format,
            "user '{username}' not found —  \
             use \"users list [search]\" to search existing users"
        );
    }

    Ok(())
}
