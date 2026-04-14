use crate::{Error, Result, commands::Context};
pub use keycloak::{AccessToken, AuthAccessToken, ClientAttributes, ClientRepresentation};
use serde::Deserialize;
use std::fmt;
use tracing::{debug, error};
use typed_builder::TypedBuilder;
use ureq::{
    Body,
    http::{HeaderValue, Response, header::AUTHORIZATION},
};

mod keycloak {
    use jsonwebtoken::jwk::JwkSet;

    include!(concat!(env!("OUT_DIR"), "/keycloak.rs"));

    include!(concat!(env!("OUT_DIR"), "/keycloak_paths.rs"));

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct OpenidConfiguration {
        #[serde(rename = "token_endpoint")]
        pub token_endpoint: String,
        #[serde(rename = "jwks_uri")]
        pub jwks_uri: String,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct AuthAccessToken {
        #[serde(rename = "access_token")]
        pub access_token: String,
        #[serde(rename = "expires_in")]
        pub expires_in: i64,
        #[serde(rename = "refresh_expires_in")]
        pub refresh_expires_in: Option<i64>,
        #[serde(rename = "refresh_token")]
        pub refresh_token: Option<String>,
        #[serde(rename = "token_type")]
        pub token_type: Option<String>,
        #[serde(rename = "not-before-policy")]
        pub not_before_policy: Option<i64>,
        #[serde(rename = "session_state")]
        pub session_state: Option<String>,
        #[serde(rename = "scope")]
        pub scope: Option<String>,
    }

    fn deserialize_bool_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.and_then(|v| v.parse().ok()))
    }

    fn deserialize_i64_string<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.and_then(|v| v.parse().ok()))
    }

    fn deserialize_jwks_string<'de, D>(deserializer: D) -> Result<Option<JwkSet>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(s.map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(<D::Error as serde::de::Error>::custom)?)
    }

    /// Strongly-typed view of `ClientRepresentation.attributes`.
    ///
    /// Keys sourced from Keycloak's `OIDCConfigAttributes`, `OAuth2IdentityProviderConfig`,
    /// and `OIDCIdentityProviderConfig`.
    #[allow(unused)]
    #[derive(Debug, Clone, Default, serde::Deserialize)]
    pub struct ClientAttributes {
        // ── OIDCConfigAttributes ──────────────────────────────────────────

        // Signature / encryption algorithms
        #[serde(rename = "user.info.response.signature.alg")]
        pub user_info_response_signature_alg: Option<String>,
        #[serde(rename = "user.info.encrypted.response.alg")]
        pub user_info_encrypted_response_alg: Option<String>,
        #[serde(rename = "user.info.encrypted.response.enc")]
        pub user_info_encrypted_response_enc: Option<String>,

        #[serde(rename = "request.object.signature.alg")]
        pub request_object_signature_alg: Option<String>,
        #[serde(rename = "request.object.encryption.alg")]
        pub request_object_encryption_alg: Option<String>,
        #[serde(rename = "request.object.encryption.enc")]
        pub request_object_encryption_enc: Option<String>,
        /// "request or request_uri" | "request only" | "request_uri only"
        #[serde(rename = "request.object.required")]
        pub request_object_required: Option<String>,

        #[serde(rename = "request.uris")]
        pub request_uris: Option<String>,

        #[serde(rename = "id.token.signed.response.alg")]
        pub id_token_signed_response_alg: Option<String>,
        #[serde(rename = "id.token.encrypted.response.alg")]
        pub id_token_encrypted_response_alg: Option<String>,
        #[serde(rename = "id.token.encrypted.response.enc")]
        pub id_token_encrypted_response_enc: Option<String>,

        #[serde(rename = "access.token.signed.response.alg")]
        pub access_token_signed_response_alg: Option<String>,

        #[serde(rename = "authorization.signed.response.alg")]
        pub authorization_signed_response_alg: Option<String>,
        #[serde(rename = "authorization.encrypted.response.alg")]
        pub authorization_encrypted_response_alg: Option<String>,
        #[serde(rename = "authorization.encrypted.response.enc")]
        pub authorization_encrypted_response_enc: Option<String>,

        #[serde(rename = "token.endpoint.auth.signing.alg")]
        pub token_endpoint_auth_signing_alg: Option<String>,
        #[serde(rename = "token.endpoint.auth.signing.max.exp")]
        pub token_endpoint_auth_signing_max_exp: Option<String>,

        // JWKS
        #[serde(rename = "jwks.url")]
        pub jwks_url: Option<String>,
        #[serde(
            rename = "use.jwks.url",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_jwks_url: Option<bool>,
        #[serde(
            rename = "jwks.string",
            deserialize_with = "deserialize_jwks_string",
            default
        )]
        pub jwks_string: Option<JwkSet>,
        #[serde(
            rename = "use.jwks.string",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_jwks_string: Option<bool>,

        // Session / token lifespans
        #[serde(
            rename = "access.token.lifespan",
            deserialize_with = "deserialize_i64_string",
            default
        )]
        pub access_token_lifespan: Option<i64>,
        #[serde(
            rename = "client.session.idle.timeout",
            deserialize_with = "deserialize_i64_string",
            default
        )]
        pub client_session_idle_timeout: Option<i64>,
        #[serde(
            rename = "client.session.max.lifespan",
            deserialize_with = "deserialize_i64_string",
            default
        )]
        pub client_session_max_lifespan: Option<i64>,
        #[serde(
            rename = "client.offline.session.idle.timeout",
            deserialize_with = "deserialize_i64_string",
            default
        )]
        pub client_offline_session_idle_timeout: Option<i64>,
        #[serde(
            rename = "client.offline.session.max.lifespan",
            deserialize_with = "deserialize_i64_string",
            default
        )]
        pub client_offline_session_max_lifespan: Option<i64>,

        // Auth response
        #[serde(
            rename = "exclude.session.state.from.auth.response",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub exclude_session_state_from_auth_response: Option<bool>,
        #[serde(
            rename = "exclude.issuer.from.auth.response",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub exclude_issuer_from_auth_response: Option<bool>,

        // mTLS / DPoP
        #[serde(
            rename = "tls.client.certificate.bound.access.tokens",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_mtls_hok_token: Option<bool>,
        #[serde(
            rename = "dpop.bound.access.tokens",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub dpop_bound_access_tokens: Option<bool>,

        // PKCE
        #[serde(rename = "pkce.code.challenge.method")]
        pub pkce_code_challenge_method: Option<String>,

        // Logout
        #[serde(rename = "backchannel.logout.url")]
        pub backchannel_logout_url: Option<String>,
        #[serde(
            rename = "backchannel.logout.session.required",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub backchannel_logout_session_required: Option<bool>,
        #[serde(
            rename = "backchannel.logout.revoke.offline.tokens",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub backchannel_logout_revoke_offline_tokens: Option<bool>,
        #[serde(rename = "frontchannel.logout.url")]
        pub frontchannel_logout_url: Option<String>,
        #[serde(
            rename = "frontchannel.logout.session.required",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub frontchannel_logout_session_required: Option<bool>,
        #[serde(
            rename = "logout.confirmation.enabled",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub logout_confirmation_enabled: Option<bool>,
        #[serde(rename = "post.logout.redirect.uris")]
        pub post_logout_redirect_uris: Option<String>,

        // Refresh tokens
        #[serde(
            rename = "client_credentials.use_refresh_token",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_refresh_token_for_client_credentials_grant: Option<bool>,
        #[serde(
            rename = "use.refresh.tokens",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_refresh_tokens: Option<bool>,

        // Token response format
        #[serde(
            rename = "token.response.type.bearer.lower-case",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_lower_case_in_token_response: Option<bool>,
        #[serde(
            rename = "access.token.header.type.rfc9068",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub use_rfc9068_access_token_header_type: Option<bool>,
        #[serde(
            rename = "id.token.as.detached.signature",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub id_token_as_detached_signature: Option<bool>,

        // Token exchange
        #[serde(
            rename = "standard.token.exchange.enabled",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub standard_token_exchange_enabled: Option<bool>,
        #[serde(
            rename = "standard.token.exchange.enableRefreshRequestedTokenType",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub standard_token_exchange_refresh_enabled: Option<bool>,

        // JWT Authorization Grant
        #[serde(
            rename = "oauth2.jwt.authorization.grant.enabled",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub jwt_authorization_grant_enabled: Option<bool>,
        #[serde(rename = "oauth2.jwt.authorization.grant.idp")]
        pub jwt_authorization_grant_idp: Option<String>,
        #[serde(rename = "oauth2.jwt.authorization.grant.audience")]
        pub jwt_authorization_grant_audience: Option<String>,

        // External token
        #[serde(
            rename = "external.token.enabled",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub external_token_enabled: Option<bool>,
        #[serde(rename = "external.token.idp")]
        pub external_token_idp: Option<String>,

        // Client metadata URIs
        #[serde(rename = "logoUri")]
        pub logo_uri: Option<String>,
        #[serde(rename = "tosUri")]
        pub tos_uri: Option<String>,
        #[serde(rename = "policyUri")]
        pub policy_uri: Option<String>,
        #[serde(rename = "sectorIdentifierUri")]
        pub sector_identifier_uri: Option<String>,

        #[serde(
            rename = "realm_client",
            deserialize_with = "deserialize_bool_string",
            default
        )]
        pub realm_client: Option<bool>,
    }
}

fn as_json<T>(res: Response<Body>) -> Result<T>
where
    for<'de> T: Deserialize<'de>,
{
    let status = res.status();
    let mut body = res.into_body();

    if let Some(mime_type) = body.mime_type()
        && mime_type.contains(mime::APPLICATION_JSON.essence_str())
    {
        let json = if tracing::enabled!(tracing::Level::DEBUG) {
            let raw = body.read_to_string()?;
            debug!(body = raw, status_code = status.as_u16(), "raw body");
            serde_json::from_str(&raw).map_err(Error::from)
        } else {
            body.read_json().map_err(Error::from)
        };

        json.inspect_err(|error| {
            error!(
                status_code = status.as_u16(),
                %error,
                "failed to deserialize json"
            );
        })
        .map_err(Error::from)
    } else {
        Err(Error::msg("response is not json"))
    }
}

fn handle_response(res: Response<Body>) -> Result<Response<Body>> {
    let status = res.status();
    match status.as_u16() {
        200..=299 => Ok(res),
        _ => {
            let message = res
                .into_body()
                .read_to_string()
                .inspect_err(|error| {
                    error!(status_code = status.as_u16(), %error, "failed to read body");
                })
                .unwrap_or_default();

            error!(
                status_code = status.as_u16(),
                error = status.as_str(),
                message,
                "http request failed"
            );

            Err(Error::msg("http request failed"))
        }
    }
}

#[derive(TypedBuilder)]
pub struct AdminCliClient {
    name: String,
    server_url: String,
    context: Context,
}

impl AdminCliClient {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn realm(&self) -> &str {
        &self.context.realm
    }

    fn endpoint<S>(&self, path: S) -> String
    where
        S: fmt::Display,
    {
        format!("{}{}", self.server_url(), path)
    }

    fn openid_configuration(&self) -> Result<keycloak::OpenidConfiguration> {
        let realm = self.realm();
        let openid_config_url = format!(
            "{}/realms/{}/.well-known/openid-configuration",
            self.server_url, realm
        );
        let res = ureq::get(&openid_config_url).call().inspect_err(|error| {
            error!(url = %openid_config_url, realm, %error, "failed to fetch openid configuration")
        })?;
        let res = handle_response(res)?;
        as_json(res)
    }

    pub fn jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet> {
        let openid_config = self.openid_configuration()?;
        let res = ureq::get(&openid_config.jwks_uri).call().inspect_err(
            |error| error!(url = %openid_config.jwks_uri, %error, "failed to fetch jwks"),
        )?;
        let res = handle_response(res)?;
        as_json(res).inspect(|jwks| {
            debug!(
                server_url = self.server_url,
                realm = self.realm(),
                openid_config = serde_json::to_string(&openid_config).unwrap_or_default(),
                jwks = serde_json::to_string(&jwks).unwrap_or_default(),
                "jwks"
            )
        })
    }

    pub fn token(&mut self) -> Result<keycloak::AuthAccessToken> {
        let username = match &self.context.username {
            Some(p) => p,
            None => {
                return Err(Error::ContextMissingUsername);
            }
        };
        let password = match self.context.get_password()? {
            Some(p) => p,
            None => {
                return Err(Error::ContextMissingPassword);
            }
        };

        let keycloak::OpenidConfiguration { token_endpoint, .. } = self.openid_configuration()?;
        let res = ureq::post(&token_endpoint)
            .content_type(mime::APPLICATION_WWW_FORM_URLENCODED.essence_str())
            .send_form([
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", username),
                ("password", &password),
            ])
            .inspect_err(|error| error!(%error, endpoint = token_endpoint, "http failure"))?;
        let res = handle_response(res)?;
        let at = as_json::<keycloak::AuthAccessToken>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint = token_endpoint,
                "failed to deserialize token"
            );
        })?;

        self.context.set_token(&self.name, &at)?;

        Ok(at)
    }

    pub fn refresh(&mut self) -> Result<keycloak::AuthAccessToken> {
        let now = now_epoch();
        let token = self
            .context
            .get_token()?
            .ok_or_else(|| Error::AuthNoTokenFound)?;
        let AuthAccessToken {
            access_token,
            expires_in,
            refresh_token,
            refresh_expires_in,
            ..
        } = &token;
        let iat = token_iat(&access_token).unwrap_or(now);
        if iat + expires_in > now {
            debug!("access token still valid");
            return Ok(token);
        }

        let (rei, refresh_token) = match (refresh_expires_in, refresh_token) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                error!(
                    name = self.name,
                    "attempted refresh but no sitting token found"
                );
                let msg = "no token found for refresh";
                println!("{msg}");
                return Err(Error::msg(msg));
            }
        };
        let refresh_ok = iat + rei > now;
        if !refresh_ok {
            debug!("refresh token expired. attempting to login with sitting grants");
            return self.token();
        }

        let keycloak::OpenidConfiguration { token_endpoint, .. } = self.openid_configuration()?;
        let res = ureq::post(&token_endpoint)
            .content_type(mime::APPLICATION_WWW_FORM_URLENCODED.essence_str())
            .send_form([
                ("grant_type", "refresh_token"),
                ("client_id", "admin-cli"),
                ("refresh_token", &refresh_token),
            ])
            .inspect_err(|error| error!(%error, endpoint = token_endpoint, "http failure"))?;
        let res = handle_response(res)?;
        let at = as_json(res).inspect_err(|error| {
            error!(
                %error,
                endpoint = token_endpoint,
                "failed to deserialize refreshed token"
            );
        })?;

        self.context.set_token(&self.name, &at)?;

        Ok(at)
    }

    pub fn consume(self) -> (String, Context) {
        (self.name, self.context)
    }

    fn authorize(&mut self) -> Result<HeaderValue> {
        let token = self.refresh().or_else(|err| {
            if matches!(err, Error::AuthNoTokenFound) {
                self.token()
            } else {
                Err(err)
            }
        })?;
        let AuthAccessToken {
            access_token,
            token_type,
            ..
        } = &token;
        let auth = format!(
            "{} {access_token}",
            token_type.as_deref().unwrap_or("Bearer")
        );
        Ok(HeaderValue::from_str(&auth).inspect_err(|error| {
            error!(%error, "invalid authorization header bytes");
        })?)
    }
}

// clients

impl AdminCliClient {
    pub fn clients_list(
        &mut self,
        realm: &str,
        page_size: u64,
        offset: u64,
        search: Option<&str>,
        exact: bool,
    ) -> Result<Vec<keycloak::ClientRepresentation>> {
        let auth_header = self.authorize()?;

        let endpoint = self.endpoint(keycloak::paths::realms_realm_clients_get(realm));
        let mut query = vec![
            ("max", page_size.to_string()),
            ("first", offset.to_string()),
        ];
        if let Some(search) = search {
            query.push(("clientId", search.to_string()));
            query.push(("search", (!exact).to_string()));
        }
        let res = ureq::get(&endpoint)
            .query_pairs(query)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        as_json::<Vec<keycloak::ClientRepresentation>>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint,
                "failed to deserialize list of clients"
            );
        })
    }

    pub fn client_describe(
        &mut self,
        realm: &str,
        client_id: &str,
    ) -> Result<Option<keycloak::ClientRepresentation>> {
        Ok(self.clients_list(realm, 1, 0, Some(client_id), true)?.pop())
    }
}

fn now_epoch() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn token_iat(jwt: &str) -> Option<i64> {
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};

    #[derive(serde::Deserialize)]
    struct Claims {
        iat: Option<i64>,
    }
    let payload = jwt.split('.').nth(1)?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims = serde_json::from_slice::<Claims>(&bytes).ok()?;
    claims.iat
}
