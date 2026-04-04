use super::{coalesce_realm, load_context_or_current, save_config};
use crate::{
    Error, Result,
    cli::OutputFormat,
    client::{AccessToken, AdminCliClient, AuthAccessToken},
    out,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use colored::Colorize;
use jsonwebtoken::{DecodingKey, Validation, decode_header};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error};

const LABEL_WIDTH: usize = 20;

fn print_field(label: &str, value: impl fmt::Display) {
    let label = format!("{label}:");
    println!(
        "    {} {value}",
        format!("{label:<width$}", width = LABEL_WIDTH).dimmed(),
    );
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn fmt_relative(secs: i64) -> String {
    let abs = secs.unsigned_abs();
    let d = abs / 86400;
    let h = (abs % 86400) / 3600;
    let m = (abs % 3600) / 60;
    let s = abs % 60;
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    let dur = parts.join(" ");
    if secs >= 0 {
        format!("in {dur}")
    } else {
        format!("{dur} ago")
    }
}

pub fn logout(name: Option<String>) -> Result<()> {
    let (name, ctx, mut config) = load_context_or_current(name.as_deref()).inspect_err(|err| {
        if matches!(err, Error::ContextSelection) {
            out!(
                "no context name given and no active context —  \
                 pass a name or set one with \"context use\""
            );
        }
    })?;

    ctx.delete_token()?;
    config.contexts.entry(name).insert_entry(ctx);

    println!("logged out!");

    save_config(&config)
}

pub fn login(name: Option<String>, realm: String) -> Result<()> {
    let (name, ctx, mut config) = load_context_or_current(name.as_deref()).inspect_err(|err| {
        if matches!(err, Error::ContextSelection) {
            out!(
                "no context name given and no active context —  \
                 pass a name or set one with \"context use\""
            );
        }
    })?;

    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            println!(
                "cannot find server-url on current context —  \
                 use \"context update --server-url <url>\""
            );
            return Err(Error::msg("missing server-url"));
        }
    };

    let mut client = AdminCliClient::builder()
        .name(name)
        .server_url(server_url.clone())
        .realm(realm.clone())
        .context(ctx)
        .build();
    client.refresh().inspect_err(|err| {
        if matches!(err, Error::ContextMissingUsername) {
            out!(
                "cannot find username on current context —  \
                 use \"context update --username <username>\""
            );
        } else if matches!(err, Error::ContextMissingPassword) {
            out!(
                "cannot find password on current context —  \
                 use \"context update --username <username>\""
            );
        }
    })?;

    let (name, ctx) = client.consume();
    config.contexts.entry(name).insert_entry(ctx);

    println!("logged in!");

    save_config(&config)
}

pub fn status(name: Option<String>, realm: String, format: OutputFormat) -> Result<()> {
    let (name, ctx, _) = load_context_or_current(name.as_deref()).inspect_err(|err| {
        if matches!(err, Error::ContextSelection) {
            out!(
                "no context name given and no active context —  \
                 pass a name or set one with \"context use\""
            );
        }
    })?;
    let (token, refresh_expires_in) = match ctx.get_token()? {
        Some(AuthAccessToken {
            access_token,
            refresh_expires_in,
            ..
        }) => (access_token, refresh_expires_in),
        None => {
            out!(
                "no token found on current context —  \
                 use \"authorize login\" to obtain one"
            );

            return Ok(());
        }
    };

    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            out!(
                "cannot find server-url on current context —  \
                 use \"context update --server-url <url>\""
            );

            return Err(Error::MissingArgument);
        }
    };

    let realm = match coalesce_realm(&ctx, Some(realm.as_str())) {
        Some(r) => r.to_string(),
        None => {
            out!(
                "cannot find realm on current context —  \
                 use \"context update --realm <realm>\""
            );

            return Err(Error::MissingArgument);
        }
    };

    let client = AdminCliClient::builder()
        .name(name)
        .server_url(server_url)
        .realm(realm)
        .context(ctx)
        .build();

    let jwks = client.jwks()?;
    let header = decode_header(&token).inspect_err(|error| {
        error!(
            %error,
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            "failed to decode token header"
        )
    })?;

    let kid = header.kid.ok_or_else(|| {
        debug!(
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            %token,
            "validation context"
        );

        out!(
            "invalid authorization status —  \
             use \"authorize login\""
        );

        return Error::JwtMissingKid;
    })?;

    let jwk = jwks.find(&kid).ok_or_else(|| {
        debug!(
            kid,
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            %token,
            "validation context"
        );

        out!(
            "invalid authorization status —  \
             use \"authorize login\""
        );

        return Error::JwksMissingKid;
    })?;

    let decoding_key = DecodingKey::try_from(jwk).map_err(|error| {
        debug!(
            kid,
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            %token,
            "validation context"
        );

        error!(%error, kid, "failed to build decoding key");

        out!(
            "invalid authorization status —  \
             use \"authorize login\""
        );

        return error;
    })?;

    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<AccessToken>(&token, &decoding_key, &validation)
        .inspect_err(|error| {
            debug!(
                kid,
                jwks = serde_json::to_string(&jwks).unwrap_or_default(),
                %token,
                ?validation,
                "validation context"
            );

            error!(%error, kid, "failed to validate token");
        });

    let (result, t) = match token_data {
        Ok(t) => (Ok(()), t.claims),
        Err(error) => {
            let claims = token.split('.').skip(1).take(1).collect::<Vec<_>>();
            let claims = claims.first().ok_or(Error::JwtInvalidClaims)?;
            let claims = BASE64_URL_SAFE_NO_PAD
                .decode(*claims)
                .inspect_err(|error| error!(%error, claims, "failed to decode claims"))?;
            let claims = serde_json::from_slice::<AccessToken>(&claims)
                .inspect_err(|error| error!(%error, "failed to parse claims"))?;
            (Err(error), claims)
        }
    };
    let now = now_epoch();

    match format {
        OutputFormat::Json => {
            let mut map = serde_json::Map::new();
            if let Some(v) = &t.sub {
                map.insert("sub".into(), v.clone().into());
            }
            if let Some(v) = &t.preferred_username {
                map.insert("preferred-username".into(), v.clone().into());
            }
            if let Some(v) = &t.name {
                map.insert("name".into(), v.clone().into());
            }
            if let Some(v) = &t.given_name {
                map.insert("given-name".into(), v.clone().into());
            }
            if let Some(v) = &t.family_name {
                map.insert("family-name".into(), v.clone().into());
            }
            if let Some(v) = &t.email {
                map.insert("email".into(), v.clone().into());
            }
            if let Some(v) = &t.iss {
                map.insert("issuer".into(), v.clone().into());
            }
            if let Some(v) = &t.azp {
                map.insert("authorized-party".into(), v.clone().into());
            }
            if let Some(v) = &t.typ {
                map.insert("type".into(), v.clone().into());
            }
            if let Some(v) = &t.scope {
                map.insert("scope".into(), v.clone().into());
            }
            if let Some(iat) = &t.iat {
                map.insert("issued-at".into(), (*iat).into());
            }
            if let Some(exp) = &t.exp {
                map.insert("expires".into(), (*exp).into());
                map.insert(
                    "status".into(),
                    if *exp > now { "valid" } else { "expired" }.into(),
                );
            }
            if let Some(rei) = &refresh_expires_in {
                if let Some(iat) = &t.iat {
                    let refresh_exp = iat + rei;
                    map.insert("refresh-expires".into(), refresh_exp.into());
                    map.insert("refreshable".into(), (refresh_exp > now).into());
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(map)).inspect_err(
                    |error| {
                        error!(%error, "failed to serialize token claims");
                    }
                )?
            );
        }
        OutputFormat::Plain => {
            println!();
            if let Some(v) = &t.sub {
                print_field("sub", v);
            }
            if let Some(v) = &t.preferred_username {
                print_field("preferred-username", v);
            }
            if let Some(v) = &t.name {
                print_field("name", v);
            }
            if let Some(v) = &t.given_name {
                print_field("given-name", v);
            }
            if let Some(v) = &t.family_name {
                print_field("family-name", v);
            }
            if let Some(v) = &t.email {
                print_field("email", v);
            }
            println!();
            if let Some(v) = &t.iss {
                print_field("issuer", v);
            }
            if let Some(v) = &t.azp {
                print_field("authorized-party", v);
            }
            if let Some(v) = &t.typ {
                print_field("type", v);
            }
            if let Some(v) = &t.scope {
                print_field("scope", v);
            }
            println!();
            if let Some(iat) = &t.iat {
                let rel = fmt_relative(*iat - now);
                print_field("issued-at", format!("{iat} ({rel})"));
            }
            if let Some(exp) = &t.exp {
                let rel = fmt_relative(*exp - now);
                print_field("expires", format!("{exp} ({rel})"));
                if *exp > now {
                    print_field("status", "valid".green());
                } else {
                    print_field("status", "expired".red());
                }
            }
            if let Some(rei) = &refresh_expires_in {
                if let Some(iat) = &t.iat {
                    let refresh_exp = iat + rei;
                    let rel = fmt_relative(refresh_exp - now);
                    print_field("refresh-expires", format!("{refresh_exp} ({rel})"));
                    if refresh_exp > now {
                        print_field("refreshable", "yes".green());
                    } else {
                        print_field("refreshable", "no".red());
                    }
                }
            }
            println!();
        }
    }

    Ok(result.inspect_err(|_| {
        out!(
            "invalid authorization status —  \
             use \"authorize login\""
        );
    })?)
}
