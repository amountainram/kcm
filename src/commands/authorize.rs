use super::{Color, Printer, load_context_or_current, save_config};
use crate::{
    Error, Result,
    client::{AccessToken, AdminCliClient, AuthAccessToken},
    out,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, Validation, decode_header};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error};

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
    let (name, ctx, mut config) = load_context_or_current(name.as_deref())?;

    ctx.delete_token()?;
    config.contexts.entry(name).insert_entry(ctx);

    out!("logged out!");

    save_config(&config)
}

pub fn login(name: Option<String>) -> Result<()> {
    let (name, ctx, mut config) = load_context_or_current(name.as_deref())?;

    let server_url = ctx
        .server_url
        .clone()
        .ok_or(Error::ContextMissingServerUrl)?;

    let mut client = AdminCliClient::builder()
        .name(name)
        .server_url(server_url.clone())
        .context(ctx)
        .build();

    client.refresh().or_else(|err| {
        if matches!(err, Error::AuthNoTokenFound) {
            client.token()
        } else {
            Err(err)
        }
    })?;

    let (name, ctx) = client.consume();
    config.contexts.entry(name).insert_entry(ctx);

    out!("logged in!");

    save_config(&config)
}

pub fn status(name: Option<String>) -> Result<()> {
    let (name, ctx, _) = load_context_or_current(name.as_deref())?;
    let (token, refresh_expires_in) = match ctx.get_token()? {
        Some(AuthAccessToken {
            access_token,
            refresh_expires_in,
            ..
        }) => (access_token, refresh_expires_in),
        None => {
            return Err(Error::MustLogin);
        }
    };

    let server_url = match &ctx.server_url {
        Some(s) => s.clone(),
        None => {
            return Err(Error::ContextMissingServerUrl);
        }
    };

    let client = AdminCliClient::builder()
        .name(name)
        .server_url(server_url)
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

        Error::JwtMissingKid
    })?;

    let jwk = jwks.find(&kid).ok_or_else(|| {
        debug!(
            kid,
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            %token,
            "validation context"
        );

        Error::JwksMissingKid
    })?;

    let decoding_key = DecodingKey::try_from(jwk).map_err(|error| {
        debug!(
            kid,
            jwks = serde_json::to_string(&jwks).unwrap_or_default(),
            %token,
            "validation context"
        );

        error!(%error, kid, "failed to build decoding key");

        Error::JwtDecodingKey
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
            error!(%error, "failed to retrieve token data");

            let claims = token.split('.').skip(1).take(1).collect::<Vec<_>>();
            let claims = claims.first().ok_or(Error::JwtInvalidClaims)?;
            let claims = BASE64_URL_SAFE_NO_PAD
                .decode(*claims)
                .inspect_err(|error| error!(%error, claims, "failed to decode claims"))?;

            debug!(
                name = client.name(),
                server_url = client.server_url(),
                realm = client.realm(),
                decoded_claims = %String::from_utf8_lossy(&claims)
            );

            let claims = serde_json::from_slice::<AccessToken>(&claims)
                .inspect_err(|error| error!(%error, "failed to parse claims"))?;

            (Err(Error::MustLogin), claims)
        }
    };
    let now = now_epoch();
    let mut printer = Printer::default();

    let mut any = false;
    printer.ln();
    if let Some(v) = &t.sub {
        printer.print_field("sub", v.to_string());
        any = true;
    }
    if let Some(v) = &t.preferred_username {
        printer.print_field("preferred-username", v.to_string());
        any = true;
    }
    if let Some(v) = &t.name {
        printer.print_field("name", v.to_string());
        any = true;
    }
    if let Some(v) = &t.given_name {
        printer.print_field("given-name", v.to_string());
        any = true;
    }
    if let Some(v) = &t.family_name {
        printer.print_field("family-name", v.to_string());
        any = true;
    }
    if let Some(v) = &t.email {
        printer.print_field("email", v.to_string());
        any = true;
    }
    if any {
        printer.ln();
    }

    any = false;
    if let Some(v) = &t.iss {
        printer.print_field("issuer", v.to_string());
        any = true;
    }
    if let Some(v) = &t.azp {
        printer.print_field("authorized-party", v.to_string());
        any = true;
    }
    if let Some(v) = &t.typ {
        printer.print_field("type", v.to_string());
        any = true;
    }
    if let Some(v) = &t.scope {
        printer.print_field("scope", v.to_string());
        any = true;
    }
    if any {
        printer.ln();
    }

    any = false;
    if let Some(iat) = &t.iat {
        let rel = fmt_relative(*iat - now);
        printer.print_field("issued-at", format!("{iat} ({rel})"));
        any = true;
    }
    if let Some(exp) = &t.exp {
        let rel = fmt_relative(*exp - now);
        printer.print_field("expires", format!("{exp} ({rel})"));
        if *exp > now {
            printer.print_field_with_color("status", "valid", Color::Green);
        } else {
            printer.print_field_with_color("status", "expired", Color::Red);
        }
        any = true;
    }
    if let Some(rei) = &refresh_expires_in {
        if let Some(iat) = &t.iat {
            let refresh_exp = iat + rei;
            let rel = fmt_relative(refresh_exp - now);
            printer.print_field("refresh-expires", format!("{refresh_exp} ({rel})"));
            if refresh_exp > now {
                printer.print_field_with_color("refreshable", "yes", Color::Green);
            } else {
                printer.print_field_with_color("refreshable", "no", Color::Red);
            }
        }
        any = true;
    }
    if any {
        printer.ln();
    }

    result
}
