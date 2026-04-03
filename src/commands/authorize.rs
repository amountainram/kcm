use crate::{
    Error, Result,
    client::{RealmClient, keycloak},
    commands::{load_context_or_current, save_config},
};
use colored::Colorize;
use jsonwebtoken::{DecodingKey, Validation, decode_header};
use tracing::error;

pub fn login(name: Option<String>) -> Result<()> {
    let (name, mut ctx, mut config) = load_context_or_current(name.as_deref())?;

    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            eprintln!(
                r#"cannot find server-url on current context. use "context update --server-url <url>""#
            );
            return Err(Error::msg("missing server-url"));
        }
    };

    let realm = match &ctx.realm {
        Some(r) => r.clone(),
        None => {
            eprintln!(
                r#"cannot find realm on current context. use "context update --realm <realm>""#
            );
            return Err(Error::msg("missing realm"));
        }
    };

    let client = RealmClient::builder()
        .server_url(server_url)
        .realm(realm)
        .context(ctx.clone())
        .build();

    let token = client.token().inspect_err(|error| {
        error!(?error, "failed to retrieve access token");
    })?;

    ctx.token.insert(serde_json::to_string(&token)?.into());
    config.contexts.entry(name).insert_entry(ctx);

    save_config(&config)
}

pub fn status(name: Option<String>) -> Result<()> {
    let (_, ctx, _) = load_context_or_current(name.as_deref())?;
    let token = match &ctx.token {
        Some(x) => x.read().to_string(),
        None => {
            eprintln!("no token found on current context. use \"authorize login\" to obtain one");
            return Ok(());
        }
    };

    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            eprintln!(
                r#"cannot find server-url on current context. use "context update --server-url <url>""#
            );
            return Err(Error::msg("missing server-url"));
        }
    };
    let realm = match &ctx.realm {
        Some(r) => r.clone(),
        None => {
            eprintln!(
                r#"cannot find realm on current context. use "context update --realm <realm>""#
            );
            return Err(Error::msg("missing realm"));
        }
    };

    let client = RealmClient::builder()
        .server_url(server_url)
        .realm(realm)
        .context(ctx)
        .build();

    let jwks = client.jwks()?;
    let header = decode_header(&token)
        .map_err(|e| Error::msg(format!("failed to decode token header: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| Error::msg("token has no kid header"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| Error::msg(format!("no matching key found in jwks for kid: {kid}")))?;

    let decoding_key = DecodingKey::try_from(jwk)
        .map_err(|e| Error::msg(format!("failed to build decoding key: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;

    let token_data =
        jsonwebtoken::decode::<keycloak::AccessToken>(&token, &decoding_key, &validation)
            .map_err(|e| Error::msg(format!("failed to validate token: {e}")))?;

    let t = &token_data.claims;

    if let Some(sub) = &t.sub {
        println!("    {} {sub}", "sub:".dimmed());
    }
    if let Some(preferred_username) = &t.preferred_username {
        println!(
            "    {} {preferred_username}",
            "preferred-username:".dimmed()
        );
    }
    if let Some(email) = &t.email {
        println!("    {} {email}", "email:".dimmed());
    }
    if let Some(name) = &t.name {
        println!("    {} {name}", "name:".dimmed());
    }
    if let Some(given_name) = &t.given_name {
        println!("    {} {given_name}", "given-name:".dimmed());
    }
    if let Some(family_name) = &t.family_name {
        println!("    {} {family_name}", "family-name:".dimmed());
    }
    if let Some(iss) = &t.iss {
        println!("    {} {iss}", "issuer:".dimmed());
    }
    if let Some(azp) = &t.azp {
        println!("    {} {azp}", "authorized-party:".dimmed());
    }
    if let Some(typ) = &t.typ {
        println!("    {} {typ}", "type:".dimmed());
    }
    if let Some(scope) = &t.scope {
        println!("    {} {scope}", "scope:".dimmed());
    }
    if let Some(exp) = &t.exp {
        println!("    {} {exp}", "exp:".dimmed());
    }
    if let Some(iat) = &t.iat {
        println!("    {} {iat}", "iat:".dimmed());
    }

    Ok(())
}
