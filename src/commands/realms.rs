use super::{OutputFormat, Printer, enforce_context, prepare_client};
use crate::{Result, client::RealmRepresentation, out, outfmt};
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

fn format_realm_row(r: &RealmRepresentation) -> String {
    let realm = r.realm.as_deref().unwrap_or("—");
    let enabled = if r.enabled.unwrap_or_default() {
        "✓".to_string().green()
    } else {
        "✗".to_string().red()
    };
    let display_name = r.display_name.as_deref().unwrap_or("");
    format!("  {enabled}  {realm:<32} {display_name}")
}

fn print_realms(page: u64, page_size: u64, realms: &[RealmRepresentation]) {
    let header = format!("     {:32} DISPLAY NAME", "REALM");
    let separator = format!("  {}", "─".repeat(60));
    out!("{}", format!("\n  page {page}\n").dimmed());
    out!("{}", format!("{header}\n").dimmed());
    out!("{}", format!("{separator}\n").dimmed());
    for r in realms {
        out!("{}", format_realm_row(r));
    }
    if realms.len() as u64 == page_size {
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

pub fn list(page_size: u64, format: OutputFormat, search: Option<String>) -> Result<()> {
    let (name, ctx) = enforce_context(format)?;
    let (_working_realm, mut client) = prepare_client(format, None, name, ctx)?;

    let mut offset = 0;
    let mut page = 1;
    let mut realms = vec![];

    loop {
        let next_page = client
            .realms_list(page_size, offset, search.as_deref())
            .inspect_err(|error| {
                error!(
                    %error,
                    page_size,
                    page,
                    offset,
                    %format,
                    "failed to fetch realms"
                );
            })?;
        let next_page_len = next_page.len() as u64;
        match format {
            OutputFormat::Json => {
                realms.extend(next_page);
            }
            OutputFormat::Plain => {
                print_realms(page, page_size, &next_page);
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
            serde_json::to_string_pretty(&realms).inspect_err(|error| {
                error!(%error, "failed to serialize realms");
            })?
        )
    } else {
        out!();
    }

    Ok(())
}

pub fn get(format: OutputFormat, realm: String) -> Result<()> {
    let (name, ctx) = enforce_context(format)?;
    let (_working_realm, mut client) = prepare_client(format, None, name, ctx)?;

    let realms = client
        .realms_list(u64::MAX, 0, Some(&realm))
        .inspect_err(|error| {
            error!(
                %error,
                %format,
                realm,
                "failed to fetch realms"
            );
        })?;

    let item = realms
        .into_iter()
        .find(|r| r.realm.as_deref() == Some(&realm));

    if let Some(r) = item {
        let mut printer = Printer::builder().format(format).label_width(32).build();
        printer.ln();
        let mut any = false;

        print_or!(any, printer, "realm", r.realm);
        print_or!(any, printer, "displayName", r.display_name);
        print_or!(any, printer, "displayNameHtml", r.display_name_html);
        print_or!(
            any,
            printer,
            "enabled",
            r.enabled,
            match r.enabled {
                Some(true) => colored::Color::Green,
                Some(false) | None => colored::Color::Red,
            }
        );

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "id", r.id);
        print_or!(
            any,
            printer,
            "defaultSignatureAlgorithm",
            r.default_signature_algorithm
        );
        print_or!(any, printer, "sslRequired", r.ssl_required);
        print_or!(any, printer, "registrationAllowed", r.registration_allowed);
        print_or!(
            any,
            printer,
            "registrationEmailAsUsername",
            r.registration_email_as_username
        );
        print_or!(
            any,
            printer,
            "loginWithEmailAllowed",
            r.login_with_email_allowed
        );
        print_or!(
            any,
            printer,
            "duplicateEmailsAllowed",
            r.duplicate_emails_allowed
        );
        print_or!(any, printer, "verifyEmail", r.verify_email);
        print_or!(any, printer, "editUsernameAllowed", r.edit_username_allowed);
        print_or!(any, printer, "rememberMe", r.remember_me);

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "bruteForceProtected", r.brute_force_protected);
        print_or!(any, printer, "permanentLockout", r.permanent_lockout);
        print_or!(
            any,
            printer,
            "internationalizationEnabled",
            r.internationalization_enabled
        );
        print_or!(
            any,
            printer,
            "userManagedAccessAllowed",
            r.user_managed_access_allowed
        );
        print_or!(
            any,
            printer,
            "organizationsEnabled",
            r.organizations_enabled
        );

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "accessTokenLifespan", r.access_token_lifespan);
        print_or!(any, printer, "accessCodeLifespan", r.access_code_lifespan);
        print_or!(
            any,
            printer,
            "ssoSessionIdleTimeout",
            r.sso_session_idle_timeout
        );
        print_or!(
            any,
            printer,
            "ssoSessionMaxLifespan",
            r.sso_session_max_lifespan
        );
        print_or!(
            any,
            printer,
            "offlineSessionIdleTimeout",
            r.offline_session_idle_timeout
        );
        print_or!(
            any,
            printer,
            "offlineSessionMaxLifespan",
            r.offline_session_max_lifespan
        );
        print_or!(
            any,
            printer,
            "refreshTokenMaxReuse",
            r.refresh_token_max_reuse
        );

        if any {
            printer.ln();
        }
        any = false;

        print_or!(any, printer, "accountTheme", r.account_theme);
        print_or!(any, printer, "adminTheme", r.admin_theme);
        print_or!(any, printer, "emailTheme", r.email_theme);
        print_or!(any, printer, "loginTheme", r.login_theme);

        if any {
            printer.ln();
        }
    } else {
        outfmt!(
            format,
            "realm '{realm}' not found —  \
             use \"realms list [search]\" to search existing realms"
        );
    }

    Ok(())
}
