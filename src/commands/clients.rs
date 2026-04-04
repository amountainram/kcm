use super::{Context, OutputFormat, enforce_context};
use crate::{
    Error, Result,
    client::{AdminCliClient, ClientRepresentation},
    out, outfmt,
};
use colored::Colorize;
use std::io::{IsTerminal, stdin};
use tracing::error;

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
            .clients_list(&working_realm, page_size, offset, search.as_deref())
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
