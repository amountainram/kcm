use crate::{Error, Result, commands::Context};
use serde::Deserialize;
use tracing::error;
use typed_builder::TypedBuilder;
use ureq::{Body, http::Response};

pub mod keycloak {
    include!(concat!(env!("OUT_DIR"), "/keycloak.rs"));

    include!(concat!(env!("OUT_DIR"), "/keycloak_paths.rs"));

    #[derive(serde::Deserialize)]
    pub struct OpenidConfiguration {
        #[serde(rename = "token_endpoint")]
        pub token_endpoint: String,
        #[serde(rename = "jwks_uri")]
        pub jwks_uri: String,
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
        body.read_json()
            .inspect_err(|error| {
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
    pub fn context(&self) -> &Context {
        &self.context
    }

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
        as_json(res)
    }

    pub fn token(&self) -> Result<keycloak::AccessToken> {
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
        let res = ureq::post(token_endpoint)
            .content_type(mime::APPLICATION_WWW_FORM_URLENCODED.essence_str())
            .send_form([
                ("grant_type", "password"),
                ("client_id", "admin_cli"),
                ("username", username),
                ("password", password),
            ])?;
        let res = handle_response(res)?;
        let token = as_json::<keycloak::AccessToken>(res)?;

        println!("{token:#?}");
        todo!()
    }
}

fn a() {
    keycloak::paths::realms_get();
}
