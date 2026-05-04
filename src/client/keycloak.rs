use super::serde_helpers::{
    bool_as_string, config_to_string_map, config_to_string_vec_map, i64_as_string, jwks_as_string,
};
use crate::cli::JsonPatchMode;
use jsonwebtoken::jwk::JwkSet;

include!(concat!(env!("OUT_DIR"), "/keycloak.rs"));

include!(concat!(env!("OUT_DIR"), "/keycloak_paths.rs"));

#[derive(serde::Deserialize, serde::Serialize)]
pub struct OpenidConfiguration {
    // ── Required (per OpenID Connect Discovery 1.0) ───────────────────
    #[serde(rename = "issuer")]
    pub issuer: String,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: String,
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: String,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Vec<String>,
    #[serde(rename = "subject_types_supported")]
    pub subject_types_supported: Vec<String>,
    #[serde(rename = "id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Vec<String>,

    // ── Recommended / useful optional ─────────────────────────────────
    #[serde(rename = "userinfo_endpoint", skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(
        rename = "end_session_endpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub end_session_endpoint: Option<String>,
    #[serde(
        rename = "introspection_endpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub introspection_endpoint: Option<String>,
    #[serde(
        rename = "revocation_endpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_endpoint: Option<String>,
    #[serde(
        rename = "scopes_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(
        rename = "grant_types_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(
        rename = "token_endpoint_auth_methods_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(
        rename = "code_challenge_methods_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(
        rename = "claims_supported",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub claims_supported: Option<Vec<String>>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct AuthAccessToken {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "id_token")]
    pub id_token: Option<String>,
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

pub mod settings {
    pub const MASTER_REALM: &str = "master";
    pub const ROLE_ADMIN: &str = "admin";

    pub const CLIENT_AUTHENTICATOR_TYPE_SECRET: &str = "client-secret";
    pub const CLIENT_AUTHENTICATOR_TYPE_X509: &str = "client-x509";
    pub const CLIENT_AUTHENTICATOR_TYPE_JWT: &str = "client-jwt";
    pub const CLIENT_AUTHENTICATOR_TYPE_SECRET_JWT: &str = "client-secret-jwt";

    pub const IDENTITY_PROVIDER_OIDC: &str = "oidc";
    pub const IDENTITY_PROVIDER_TYPE_USER_AUTHENTICATION: &str = "USER_AUTHENTICATION";

    pub const PKCE_CODE_CHALLENGE_METHOD_S256: &str = "S256";

    pub const CREDENTIALS_PASSWORD: &str = "password";
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
    fn from(value: ClientAttributes) -> Self {
        config_to_string_map(&value)
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

/// Strongly-typed view of `UserRepresentation.attributes`.
///
/// Keys sourced from Keycloak's `UserModel` constants and internal attribute names.
#[allow(unused)]
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct UserAttributes {
    /// Marks a user/service-account as a temporary admin.
    /// `UserModel.IS_TEMP_ADMIN_ATTR_NAME = "is_temporary_admin"`
    #[serde(
        rename = "is_temporary_admin",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_temporary_admin: Option<Vec<String>>,

    /// Reason the user was disabled.
    /// `UserModel.DISABLED_REASON = "disabledReason"`
    #[serde(
        rename = "disabledReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disabled_reason: Option<Vec<String>>,

    /// User locale preference.
    /// `UserModel.LOCALE = "locale"`
    #[serde(rename = "locale", default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<Vec<String>>,

    /// Pending email change (before verification).
    /// `UserModel.EMAIL_PENDING = "kc.email.pending"`
    #[serde(
        rename = "kc.email.pending",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_pending: Option<Vec<String>>,

    /// Decentralized Identifier.
    /// `UserModel.DID = "did"`
    #[serde(rename = "did", default, skip_serializing_if = "Option::is_none")]
    pub did: Option<Vec<String>>,
}

impl From<UserAttributes> for std::collections::HashMap<String, Vec<String>> {
    fn from(value: UserAttributes) -> Self {
        config_to_string_vec_map(&value)
    }
}

/// Strongly-typed view of `IdentityProviderRepresentation.config`.
///
/// Keys sourced from Keycloak's `OAuth2IdentityProviderConfig` and
/// `OIDCIdentityProviderConfig`.
#[allow(unused)]
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct IdentityProviderConfig {
    // ── OAuth2IdentityProviderConfig ──────────────────────────────────

    // Endpoints
    #[serde(rename = "authorizationUrl", skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(rename = "tokenUrl", skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(rename = "userInfoUrl", skip_serializing_if = "Option::is_none")]
    pub user_info_url: Option<String>,
    #[serde(
        rename = "tokenIntrospectionUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_introspection_url: Option<String>,
    #[serde(rename = "logoutUrl", skip_serializing_if = "Option::is_none")]
    pub logout_url: Option<String>,

    // Client credentials
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret", skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(rename = "clientAuthMethod", skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<String>,
    #[serde(
        rename = "clientAssertionSigningAlg",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_assertion_signing_alg: Option<String>,
    #[serde(
        rename = "clientAssertionAudience",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_assertion_audience: Option<String>,

    // Scopes / prompt
    #[serde(rename = "defaultScope", skip_serializing_if = "Option::is_none")]
    pub default_scope: Option<String>,
    #[serde(rename = "prompt", skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    // PKCE
    #[serde(
        rename = "pkceEnabled",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pkce_enabled: Option<bool>,
    #[serde(rename = "pkceMethod", skip_serializing_if = "Option::is_none")]
    pub pkce_method: Option<String>,

    // UI / forwarding
    #[serde(
        rename = "uiLocales",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ui_locales: Option<bool>,
    #[serde(rename = "forwardParameters", skip_serializing_if = "Option::is_none")]
    pub forward_parameters: Option<String>,

    // Claim mappings
    #[serde(rename = "userIDClaim", skip_serializing_if = "Option::is_none")]
    pub user_id_claim: Option<String>,
    #[serde(rename = "userNameClaim", skip_serializing_if = "Option::is_none")]
    pub user_name_claim: Option<String>,
    #[serde(rename = "fullNameClaim", skip_serializing_if = "Option::is_none")]
    pub full_name_claim: Option<String>,
    #[serde(rename = "givenNameClaim", skip_serializing_if = "Option::is_none")]
    pub given_name_claim: Option<String>,
    #[serde(rename = "familyNameClaim", skip_serializing_if = "Option::is_none")]
    pub family_name_claim: Option<String>,
    #[serde(rename = "emailClaim", skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,

    // JWT headers
    #[serde(
        rename = "jwtX509HeadersEnabled",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_x509_headers_enabled: Option<bool>,

    // Short state
    #[serde(
        rename = "requiresShortStateParameter",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requires_short_state_parameter: Option<bool>,

    // ── OIDCIdentityProviderConfig ────────────────────────────────────

    // Signature validation
    #[serde(
        rename = "validateSignature",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validate_signature: Option<bool>,
    #[serde(rename = "jwksUrl", skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(
        rename = "useJwksUrl",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub use_jwks_url: Option<bool>,

    // Access token
    #[serde(
        rename = "isAccessTokenJWT",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_access_token_jwt: Option<bool>,

    // Backchannel
    #[serde(
        rename = "backchannelSupported",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub backchannel_supported: Option<bool>,

    // UserInfo
    #[serde(
        rename = "disableUserInfo",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_user_info: Option<bool>,

    // Nonce
    #[serde(
        rename = "disableNonce",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_nonce: Option<bool>,

    // Type claim check
    #[serde(
        rename = "disableTypeClaimCheck",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_type_claim_check: Option<bool>,

    // Clock skew
    #[serde(
        rename = "allowedClockSkew",
        with = "i64_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_clock_skew: Option<i64>,

    // Issuer
    #[serde(rename = "issuer", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    // Logout
    #[serde(
        rename = "sendClientIdOnLogout",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub send_client_id_on_logout: Option<bool>,
    #[serde(
        rename = "sendIdTokenOnLogout",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub send_id_token_on_logout: Option<bool>,

    // Client assertions
    #[serde(
        rename = "supportsClientAssertions",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub supports_client_assertions: Option<bool>,
    #[serde(
        rename = "supportsClientAssertionReuse",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub supports_client_assertion_reuse: Option<bool>,
    #[serde(
        rename = "allowClientIdAsAudience",
        with = "bool_as_string",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_client_id_as_audience: Option<bool>,
}

impl From<IdentityProviderConfig> for std::collections::HashMap<String, String> {
    fn from(value: IdentityProviderConfig) -> Self {
        config_to_string_map(&value)
    }
}
