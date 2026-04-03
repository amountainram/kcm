use crate::{Error, Result, commands::Context};
use serde::Deserialize;
use tracing::{debug, error};
use typed_builder::TypedBuilder;
use ureq::{Body, http::Response};

pub mod keycloak {
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
                ?error,
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
                    error!(status_code = status.as_u16(), ?error, "failed to read body");
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
pub struct RealmClient {
    server_url: String,
    realm: String,
    context: Context,
}

impl RealmClient {
    fn openid_configuration(&self) -> Result<keycloak::OpenidConfiguration> {
        let realm = self.realm.as_str();
        let openid_config_url = format!(
            "{}/realms/{}/.well-known/openid-configuration",
            self.server_url, realm
        );
        let res = ureq::get(&openid_config_url).call().inspect_err(|error| {
            error!(url = %openid_config_url, realm, ?error, "failed to fetch openid configuration")
        })?;
        let res = handle_response(res)?;
        as_json(res)
    }

    pub fn jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet> {
        let openid_config = self.openid_configuration()?;
        let res = ureq::get(&openid_config.jwks_uri).call().inspect_err(
            |error| error!(url = %openid_config.jwks_uri, ?error, "failed to fetch jwks"),
        )?;
        let res = handle_response(res)?;
        as_json(res).inspect(|jwks| {
            debug!(
                server_url = self.server_url,
                realm = self.realm,
                openid_config = serde_json::to_string(&openid_config).unwrap_or_default(),
                jwks = serde_json::to_string(&jwks).unwrap_or_default(),
                "jwks"
            )
        })
    }

    pub fn token(&self) -> Result<keycloak::AuthAccessToken> {
        let username = match &self.context.username {
            Some(p) => p,
            None => {
                eprintln!(
                    r#"cannot find username on current context. use "context update --username <username>""#
                );
                return Err(Error::msg("missing username"));
            }
        };
        let password = match &self.context.password {
            Some(p) => p.read(),
            None => {
                eprintln!(
                    r#"cannot find password on current context. use "context update --password""#
                );
                return Err(Error::msg("missing password"));
            }
        };

        let keycloak::OpenidConfiguration { token_endpoint, .. } = self.openid_configuration()?;
        let res = ureq::post(&token_endpoint)
            .content_type(mime::APPLICATION_WWW_FORM_URLENCODED.essence_str())
            .send_form([
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", username),
                ("password", password),
            ])
            .inspect_err(|error| error!(?error, endpoint = token_endpoint, "http failure"))?;
        let res = handle_response(res)?;
        as_json(res).inspect_err(|error| {
            error!(
                ?error,
                endpoint = token_endpoint,
                "failed to deserialize token"
            );
        })
    }

    pub fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<keycloak::AuthAccessToken> {
        let keycloak::OpenidConfiguration {
            token_endpoint, ..
        } = self.openid_configuration()?;
        let res = ureq::post(&token_endpoint)
            .content_type(
                mime::APPLICATION_WWW_FORM_URLENCODED
                    .essence_str(),
            )
            .send_form([
                ("grant_type", "refresh_token"),
                ("client_id", "admin-cli"),
                ("refresh_token", refresh_token),
            ])
            .inspect_err(|error| {
                error!(
                    ?error,
                    endpoint = token_endpoint,
                    "http failure"
                )
            })?;
        let res = handle_response(res)?;
        as_json(res).inspect_err(|error| {
            error!(
                ?error,
                endpoint = token_endpoint,
                "failed to deserialize refreshed token"
            );
        })
    }
}
