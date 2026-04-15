use crate::{Error, Result, commands::Context};
pub use keycloak::{
    AccessToken, AuthAccessToken, ClientAttributes, ClientRepresentation, settings,
};
use serde::Deserialize;
use std::fmt;
use tracing::{debug, error};
use typed_builder::TypedBuilder;
use ureq::{
    Body,
    http::{HeaderValue, Response, header::AUTHORIZATION},
};

mod keycloak {
    use crate::cli::JsonPatchMode;
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

    mod bool_as_string {
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
            Ok(s.and_then(|v| v.parse().ok()))
        }

        pub fn serialize<S>(value: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match value {
                Some(true) => serializer.serialize_str("true"),
                Some(false) => serializer.serialize_str("false"),
                None => serializer.serialize_none(),
            }
        }
    }

    mod i64_as_string {
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
            Ok(s.and_then(|v| v.parse().ok()))
        }

        pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match value {
                Some(n) => serializer.serialize_str(&n.to_string()),
                None => serializer.serialize_none(),
            }
        }
    }

    mod jwks_as_string {
        use super::JwkSet;
        use serde::Serialize;

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<JwkSet>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
            Ok(s.map(|s| serde_json::from_str(&s))
                .transpose()
                .map_err(<D::Error as serde::de::Error>::custom)?)
        }

        pub fn serialize<S>(value: &Option<JwkSet>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match value.as_ref() {
                Some(set) => JwkSet::serialize(set, serializer),
                None => serializer.serialize_none(),
            }
        }
    }

    pub mod settings {
        pub const CLIENT_AUTHENTICATOR_TYPE_SECRET: &str = "client-secret";
        pub const CLIENT_AUTHENTICATOR_TYPE_X509: &str = "client-x509";
        pub const CLIENT_AUTHENTICATOR_TYPE_JWT: &str = "client-jwt";
        pub const CLIENT_AUTHENTICATOR_TYPE_SECRET_JWT: &str = "client-secret-jwt";

        pub const PKCE_CODE_CHALLENGE_METHOD_S256: &str = "S256";
    }

    /// Strongly-typed view of `ClientRepresentation.attributes`.
    ///
    /// Keys sourced from Keycloak's `OIDCConfigAttributes`, `OAuth2IdentityProviderConfig`,
    /// and `OIDCIdentityProviderConfig`.
    #[allow(unused)]
    #[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
    pub struct ClientAttributes {
        // ── OIDCConfigAttributes ──────────────────────────────────────────

        // Signature / encryption algorithms
        #[serde(
            rename = "user.info.response.signature.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub user_info_response_signature_alg: Option<String>,
        #[serde(
            rename = "user.info.encrypted.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub user_info_encrypted_response_alg: Option<String>,
        #[serde(
            rename = "user.info.encrypted.response.enc",
            skip_serializing_if = "Option::is_none"
        )]
        pub user_info_encrypted_response_enc: Option<String>,

        #[serde(
            rename = "request.object.signature.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub request_object_signature_alg: Option<String>,
        #[serde(
            rename = "request.object.encryption.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub request_object_encryption_alg: Option<String>,
        #[serde(
            rename = "request.object.encryption.enc",
            skip_serializing_if = "Option::is_none"
        )]
        pub request_object_encryption_enc: Option<String>,
        /// "request or request_uri" | "request only" | "request_uri only"
        #[serde(
            rename = "request.object.required",
            skip_serializing_if = "Option::is_none"
        )]
        pub request_object_required: Option<String>,

        #[serde(rename = "request.uris", skip_serializing_if = "Option::is_none")]
        pub request_uris: Option<String>,

        #[serde(
            rename = "id.token.signed.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub id_token_signed_response_alg: Option<String>,
        #[serde(
            rename = "id.token.encrypted.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub id_token_encrypted_response_alg: Option<String>,
        #[serde(
            rename = "id.token.encrypted.response.enc",
            skip_serializing_if = "Option::is_none"
        )]
        pub id_token_encrypted_response_enc: Option<String>,

        #[serde(
            rename = "access.token.signed.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub access_token_signed_response_alg: Option<String>,

        #[serde(
            rename = "authorization.signed.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub authorization_signed_response_alg: Option<String>,
        #[serde(
            rename = "authorization.encrypted.response.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub authorization_encrypted_response_alg: Option<String>,
        #[serde(
            rename = "authorization.encrypted.response.enc",
            skip_serializing_if = "Option::is_none"
        )]
        pub authorization_encrypted_response_enc: Option<String>,

        #[serde(
            rename = "token.endpoint.auth.signing.alg",
            skip_serializing_if = "Option::is_none"
        )]
        pub token_endpoint_auth_signing_alg: Option<String>,
        #[serde(
            rename = "token.endpoint.auth.signing.max.exp",
            skip_serializing_if = "Option::is_none"
        )]
        pub token_endpoint_auth_signing_max_exp: Option<String>,

        // JWKS
        #[serde(rename = "jwks.url", skip_serializing_if = "Option::is_none")]
        pub jwks_url: Option<String>,
        #[serde(
            rename = "use.jwks.url",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_jwks_url: Option<bool>,
        #[serde(
            rename = "jwks.string",
            with = "jwks_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub jwks_string: Option<JwkSet>,
        #[serde(
            rename = "use.jwks.string",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_jwks_string: Option<bool>,

        // Session / token lifespans
        #[serde(
            rename = "access.token.lifespan",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub access_token_lifespan: Option<i64>,
        #[serde(
            rename = "client.session.idle.timeout",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_session_idle_timeout: Option<i64>,
        #[serde(
            rename = "client.session.max.lifespan",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_session_max_lifespan: Option<i64>,
        #[serde(
            rename = "client.offline.session.idle.timeout",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_offline_session_idle_timeout: Option<i64>,
        #[serde(
            rename = "client.offline.session.max.lifespan",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_offline_session_max_lifespan: Option<i64>,

        // Auth response
        #[serde(
            rename = "exclude.session.state.from.auth.response",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub exclude_session_state_from_auth_response: Option<bool>,
        #[serde(
            rename = "exclude.issuer.from.auth.response",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub exclude_issuer_from_auth_response: Option<bool>,

        // mTLS / DPoP
        #[serde(
            rename = "tls.client.certificate.bound.access.tokens",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_mtls_hok_token: Option<bool>,
        #[serde(
            rename = "dpop.bound.access.tokens",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub dpop_bound_access_tokens: Option<bool>,

        // PKCE
        #[serde(
            rename = "pkce.code.challenge.method",
            skip_serializing_if = "Option::is_none"
        )]
        pub pkce_code_challenge_method: Option<String>,

        // Logout
        #[serde(
            rename = "backchannel.logout.url",
            skip_serializing_if = "Option::is_none"
        )]
        pub backchannel_logout_url: Option<String>,
        #[serde(
            rename = "backchannel.logout.session.required",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub backchannel_logout_session_required: Option<bool>,
        #[serde(
            rename = "backchannel.logout.revoke.offline.tokens",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub backchannel_logout_revoke_offline_tokens: Option<bool>,
        #[serde(
            rename = "frontchannel.logout.url",
            skip_serializing_if = "Option::is_none"
        )]
        pub frontchannel_logout_url: Option<String>,
        #[serde(
            rename = "frontchannel.logout.session.required",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub frontchannel_logout_session_required: Option<bool>,
        #[serde(
            rename = "logout.confirmation.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub logout_confirmation_enabled: Option<bool>,
        #[serde(
            rename = "post.logout.redirect.uris",
            skip_serializing_if = "Option::is_none"
        )]
        pub post_logout_redirect_uris: Option<String>,

        // Refresh tokens
        #[serde(
            rename = "client_credentials.use_refresh_token",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_refresh_token_for_client_credentials_grant: Option<bool>,
        #[serde(
            rename = "use.refresh.tokens",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_refresh_tokens: Option<bool>,

        // Token response format
        #[serde(
            rename = "token.response.type.bearer.lower-case",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_lower_case_in_token_response: Option<bool>,
        #[serde(
            rename = "access.token.header.type.rfc9068",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub use_rfc9068_access_token_header_type: Option<bool>,
        #[serde(
            rename = "id.token.as.detached.signature",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub id_token_as_detached_signature: Option<bool>,

        // Token exchange
        #[serde(
            rename = "standard.token.exchange.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub standard_token_exchange_enabled: Option<bool>,
        #[serde(
            rename = "standard.token.exchange.enableRefreshRequestedTokenType",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub standard_token_exchange_refresh_enabled: Option<bool>,

        // JWT Authorization Grant
        #[serde(
            rename = "oauth2.jwt.authorization.grant.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub jwt_authorization_grant_enabled: Option<bool>,
        #[serde(
            rename = "oauth2.jwt.authorization.grant.idp",
            skip_serializing_if = "Option::is_none"
        )]
        pub jwt_authorization_grant_idp: Option<String>,
        #[serde(
            rename = "oauth2.jwt.authorization.grant.audience",
            skip_serializing_if = "Option::is_none"
        )]
        pub jwt_authorization_grant_audience: Option<String>,

        // External token
        #[serde(
            rename = "external.token.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub external_token_enabled: Option<bool>,
        #[serde(rename = "external.token.idp")]
        pub external_token_idp: Option<String>,

        // Client metadata URIs
        #[serde(rename = "logoUri", skip_serializing_if = "Option::is_none")]
        pub logo_uri: Option<String>,
        #[serde(rename = "tosUri", skip_serializing_if = "Option::is_none")]
        pub tos_uri: Option<String>,
        #[serde(rename = "policyUri", skip_serializing_if = "Option::is_none")]
        pub policy_uri: Option<String>,
        #[serde(
            rename = "sectorIdentifierUri",
            skip_serializing_if = "Option::is_none"
        )]
        pub sector_identifier_uri: Option<String>,

        #[serde(
            rename = "realm_client",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub realm_client: Option<bool>,

        // ACR / LoA mapping
        #[serde(rename = "acr.loa.map", skip_serializing_if = "Option::is_none")]
        pub acr_loa_map: Option<String>,

        // Client introspection
        #[serde(
            rename = "client.introspection.response.allow.jwt.claim.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_introspection_response_allow_jwt_claim_enabled: Option<bool>,

        // Client secret creation time
        #[serde(
            rename = "client.secret.creation.time",
            with = "i64_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_secret_creation_time: Option<i64>,

        // Lightweight access token
        #[serde(
            rename = "client.use.lightweight.access.token.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub client_use_lightweight_access_token_enabled: Option<bool>,

        // Consent screen
        #[serde(
            rename = "display.on.consent.screen",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub display_on_consent_screen: Option<bool>,

        // JWT credential public key
        #[serde(
            rename = "jwt.credential.public.key",
            skip_serializing_if = "Option::is_none"
        )]
        pub jwt_credential_public_key: Option<String>,

        // Device authorization grant
        #[serde(
            rename = "oauth2.device.authorization.grant.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub oauth2_device_authorization_grant_enabled: Option<bool>,

        // CIBA grant
        #[serde(
            rename = "oidc.ciba.grant.enabled",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub oidc_ciba_grant_enabled: Option<bool>,

        // Pushed authorization requests
        #[serde(
            rename = "require.pushed.authorization.requests",
            with = "bool_as_string",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub require_pushed_authorization_requests: Option<bool>,
    }

    impl From<ClientAttributes> for std::collections::HashMap<String, String> {
        fn from(ref value: ClientAttributes) -> Self {
            serde_json::to_value(value)
                .map(|v| match v {
                    serde_json::Value::Object(o) => o,
                    _ => Default::default(),
                })
                .map(|o| {
                    o.into_iter()
                        .filter_map(|(k, v)| match v {
                            serde_json::Value::String(s) => Some((k, s)),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    impl ClientRepresentation {
        pub fn extend(&mut self, extra: ClientRepresentation, mode: JsonPatchMode) {
            match mode {
                JsonPatchMode::Replace => {
                    *self = extra;
                }
                JsonPatchMode::ReplaceAttributesOnly => {
                    self.attributes = extra.attributes;
                }
                JsonPatchMode::Merge => {
                    macro_rules! merge_field {
                        ($($field:ident),* $(,)?) => {
                            $(
                                if extra.$field.is_some() {
                                    self.$field = extra.$field;
                                }
                            )*
                        };
                    }

                    merge_field!(
                        admin_url,
                        always_display_in_console,
                        authorization_services_enabled,
                        authorization_settings,
                        base_url,
                        bearer_only,
                        client_authenticator_type,
                        client_id,
                        client_template,
                        consent_required,
                        description,
                        direct_access_grants_enabled,
                        enabled,
                        frontchannel_logout,
                        full_scope_allowed,
                        id,
                        implicit_flow_enabled,
                        name,
                        node_re_registration_timeout,
                        not_before,
                        origin,
                        protocol,
                        public_client,
                        registration_access_token,
                        root_url,
                        secret,
                        service_accounts_enabled,
                        standard_flow_enabled,
                        surrogate_auth_required,
                        type_,
                        use_template_config,
                        use_template_mappers,
                        use_template_scope,
                    );

                    macro_rules! merge_map {
                        ($($field:ident),* $(,)?) => {
                            $(
                                self.$field.extend(extra.$field);
                            )*
                        };
                    }

                    merge_map!(
                        access,
                        authentication_flow_binding_overrides,
                        attributes,
                        registered_nodes,
                    );

                    macro_rules! swap_vec {
                        ($($field:ident),* $(,)?) => {
                            $(
                                self.$field = extra.$field;
                            )*
                        };
                    }

                    swap_vec!(
                        default_client_scopes,
                        default_roles,
                        optional_client_scopes,
                        protocol_mappers,
                        redirect_uris,
                        web_origins,
                    );
                }
            }
        }
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
    #[builder(default)]
    admin_server_url: Option<String>,
    context: Context,
    #[builder(default = default_agent())]
    agent: ureq::Agent,
}

fn default_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

impl AdminCliClient {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn admin_server_url(&self) -> &str {
        self.admin_server_url
            .as_deref()
            .unwrap_or_else(|| self.server_url())
    }

    pub fn realm(&self) -> &str {
        &self.context.realm
    }

    fn api_endpoint<S>(&self, path: S) -> String
    where
        S: fmt::Display,
    {
        format!("{}{}", self.admin_server_url(), path)
    }

    fn openid_configuration(&self) -> Result<keycloak::OpenidConfiguration> {
        let realm = self.realm();
        let openid_config_url = format!(
            "{}/realms/{}/.well-known/openid-configuration",
            self.server_url, realm
        );
        let res = self.agent.get(&openid_config_url).call().inspect_err(|error| {
            error!(url = %openid_config_url, realm, %error, "failed to fetch openid configuration")
        })?;
        let res = handle_response(res)?;
        as_json(res)
    }

    pub fn jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet> {
        let openid_config = self.openid_configuration()?;
        let res = self.agent.get(&openid_config.jwks_uri).call().inspect_err(
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
        let res = self
            .agent
            .post(&token_endpoint)
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
        let res = self
            .agent
            .post(&token_endpoint)
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

        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_clients_get(realm));
        let mut query = vec![
            ("max", page_size.to_string()),
            ("first", offset.to_string()),
        ];
        if let Some(search) = search {
            query.push(("clientId", search.to_string()));
            query.push(("search", (!exact).to_string()));
        }
        let res = self
            .agent
            .get(&endpoint)
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

    pub fn client_create(
        &mut self,
        realm: &str,
        body: ClientRepresentation,
    ) -> Result<Option<String>> {
        let auth_header = self.authorize()?;

        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_clients_post(realm));
        let res = self
            .agent
            .post(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .send_json(&body)
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res).map_err(|error| {
            error!(%error, "failed to create client");
            Error::Conflict
        })?;

        Ok(body.client_id)
    }

    pub fn client_delete(&mut self, realm: &str, client_id: String) -> Result<()> {
        let auth_header = self.authorize()?;

        let id = self
            .client_describe(realm, &client_id)?
            .and_then(|ClientRepresentation { id, .. }| id)
            .ok_or(Error::NotFound)?;

        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_clients_client_uuid_delete(
            realm, &id,
        ));
        let res = self
            .agent
            .delete(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res).map_err(|error| {
            error!(%error, "failed to delete client");
            Error::Conflict
        })?;

        Ok(())
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
