use crate::{Error, Result, commands::Context};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
pub use keycloak::{
    AccessToken, AuthAccessToken, ClientAttributes, ClientRepresentation, CredentialRepresentation,
    IdentityProviderConfig, IdentityProviderRepresentation, OpenidConfiguration, UserAttributes,
    UserRepresentation, settings,
};
use rand::{TryRng, rngs::SysRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, error};
use typed_builder::TypedBuilder;
use ureq::{
    Body,
    http::{HeaderValue, Response},
};

mod clients;
mod keycloak;
mod realm;
mod serde_helpers;
mod users;

pub mod oauth2 {
    pub const CLIENT_SECRET_BASIC: &str = "client_secret_basic";
    pub const CLIENT_SECRET_POST: &str = "client_secret_post";
    pub const CLIENT_SECRET_JWT: &str = "client_secret_jwt";
    pub const PRIVATE_KEY_JWT: &str = "private_key_jwt";
    pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";
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
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

/// Generates an OAuth 2.0 `state` value (CSRF token).
/// No strict format in the spec; 128-bit random, base64url is a good default.
fn generate_state() -> String {
    let mut bytes = [0u8; 16]; // 128 bits
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Generates a PKCE code_verifier per [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1)
/// - length 43..=128
/// - characters from the unreserved set (we use URL-safe base64, which is valid)
fn generate_code_verifier() -> String {
    // 32 random bytes -> 43-char base64url (no padding), within 43..128
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the S256 code_challenge from a code_verifier [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2)
fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier);
    BASE64_URL_SAFE_NO_PAD.encode(digest)
}

/// Optional: OIDC `nonce` (if you request `openid` and expect an ID Token).
fn generate_nonce() -> String {
    generate_code_verifier()
}

pub(crate) fn fetch_openid_configuration(url: &str) -> Result<OpenidConfiguration> {
    let agent = default_agent();
    let res = agent
        .get(url)
        .call()
        .inspect_err(|error| error!(url, %error, "failed to fetch openid configuration"))?;
    let res = handle_response(res)?;
    as_json(res)
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
        fetch_openid_configuration(&openid_config_url).inspect_err(|error| {
            error!(
                url = %openid_config_url,
                realm,
                %error,
                "failed to fetch openid configuration"
            )
        })
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

    pub fn logout(&mut self) -> Result<()> {
        let client_id = match self.context.client_id.as_deref() {
            None | Some("admin-cli") => {
                return Ok(());
            }
            Some(x) => x,
        };
        let OpenidConfiguration {
            end_session_endpoint,
            ..
        } = self.openid_configuration()?;
        if let Some(logout_endpoint) = end_session_endpoint {
            let mut logout_url = url::Url::parse(&logout_endpoint)
                .inspect_err(|error| error!(%error, logout_endpoint, "invalid logout endpoint"))?;
            let AuthAccessToken { id_token, .. } = match self.context.get_token()? {
                Some(x) => x,
                None => {
                    return Ok(());
                }
            };
            let (addr_rx, logout_rx, abort_signal_tx) = daemon::launch_logout();
            let logout_result = (move || {
                let redirect_uri = addr_rx
                    .recv()
                    .inspect_err(|_| {
                        error!(logout_endpoint, client_id, "logout daemon failed to start")
                    })
                    .map_err(Error::from)
                    .and_then(|x| x)
                    .map(|x| format!("http://{x}"))?;

                {
                    let mut qs = logout_url.query_pairs_mut();
                    if let Some(id_token) = id_token.as_deref() {
                        qs.append_pair("id_token_hint", id_token);
                    }
                    qs.append_pair("client_id", client_id)
                        .append_pair("post_logout_redirect_uri", &redirect_uri)
                        .finish();
                }

                debug!(url = %logout_url, "opening web browser");
                webbrowser::open(logout_url.as_str()).inspect_err(
                    |error| error!(%error, url = %logout_url, "failed to open web browser"),
                )?;

                logout_rx
                    .recv()
                    .inspect_err(|_| {
                        error!(
                            logout_endpoint,
                            client_id, "failed to receive logout confirmation from daemon"
                        )
                    })
                    .map_err(Error::from)
                    .and_then(|x| x)
            })();

            logout_result
                .and_then(|_| self.context.delete_token())
                .inspect_err(|_| {
                    let _ = abort_signal_tx.send(()).inspect_err(|_| {
                        error!("failed to abort daemon thread");
                    });
                })
        } else {
            self.context.delete_token()
        }
    }

    fn direct_grant_token(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let keycloak::OpenidConfiguration { token_endpoint, .. } = self.openid_configuration()?;
        Ok(self
            .agent
            .post(&token_endpoint)
            .content_type(mime::APPLICATION_WWW_FORM_URLENCODED.essence_str())
            .send_form([
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", username),
                ("password", password),
            ])
            .inspect_err(|error| error!(%error, endpoint = token_endpoint, "http failure"))?)
    }

    fn authorization_code_grant_token(
        &self,
        client_id: &str,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let keycloak::OpenidConfiguration {
            authorization_endpoint,
            token_endpoint,
            ..
        } = self.openid_configuration()?;
        let mut authorize_url = url::Url::parse(&authorization_endpoint).inspect_err(
            |error| error!(%error, authorization_endpoint, "invalid authorization endpoint"),
        )?;

        let (addr_rx, code_rx, abort_signal_tx) = daemon::launch_authorize();
        let authorization_code_flow_result = (move || {
            let redirect_uri = addr_rx
                .recv()
                .inspect_err(|_| {
                    error!(
                        authorization_endpoint,
                        token_endpoint, client_id, "authorization code daemon failed to start"
                    )
                })
                .map_err(Error::from)
                .and_then(|x| x)
                .map(|x| format!("http://{x}"))?;
            let code_verifier = generate_code_verifier();
            let state = generate_state();
            let nonce = generate_nonce();
            authorize_url
                .query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("code_challenge_method", "S256")
                .append_pair("code_challenge", &code_challenge_s256(&code_verifier))
                .append_pair("scope", "openid email profile")
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .finish();

            debug!(url = %authorize_url, "opening web browser");
            webbrowser::open(authorize_url.as_str()).inspect_err(
                |error| error!(%error, url = %authorize_url, "failed to open web browser"),
            )?;

            let authorize_response = code_rx
                .recv()
                .inspect_err(|_| {
                    error!(
                        authorization_endpoint,
                        token_endpoint, client_id, "failed to receive an authorization code daemon"
                    )
                })
                .map_err(Error::from)
                .and_then(|x| x)?;
            let code = match authorize_response {
                daemon::AuthorizeResponse::Ok {
                    code,
                    state: response_state,
                } => {
                    if response_state != state {
                        error!("failed to authorize with mismatching state codes");
                        return Err(Error::MustLogin);
                    }

                    code
                }
                daemon::AuthorizeResponse::Err {
                    error,
                    error_description,
                    state: response_state,
                } => {
                    if let Some(response_state) = response_state
                        && response_state != state
                    {
                        error!("failed to authorize with mismatching state codes");
                        return Err(Error::MustLogin);
                    }

                    error!(%error, ?error_description, "failed to authorize");
                    return Err(Error::MustLogin);
                }
            };

            Ok(self
                .agent
                .post(&token_endpoint)
                .send_form([
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", client_id),
                    ("redirect_uri", &redirect_uri),
                    ("code_verifier", &code_verifier),
                ])
                .inspect_err(|error| error!(%error, endpoint = token_endpoint, "http failure"))?)
        })();

        authorization_code_flow_result.inspect_err(|_| {
            let _ = abort_signal_tx.send(()).inspect_err(|_| {
                error!("failed to abort daemon thread");
            });
        })
    }

    pub fn token(&mut self) -> Result<keycloak::AuthAccessToken> {
        let res = match self.context.client_id.as_deref() {
            None | Some("admin-cli") => {
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

                self.direct_grant_token(username, &password)
            }
            Some(client_id) => self.authorization_code_grant_token(client_id),
        }?;

        let res = handle_response(res)?;
        let at = as_json::<keycloak::AuthAccessToken>(res).inspect_err(|error| {
            error!(
                %error,
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
                (
                    "client_id",
                    self.context.client_id.as_deref().unwrap_or("admin-cli"),
                ),
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

mod daemon {
    use crate::{Error, Result};
    use indoc::formatdoc;
    use serde::Deserialize;
    use std::{
        io,
        net::{SocketAddr, TcpListener, TcpStream},
        sync::mpsc,
        thread,
        time::Duration,
    };
    use tracing::{debug, error};
    use url::Url;

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub enum AuthorizeResponse {
        Ok {
            #[serde(rename = "code")]
            code: String,
            #[serde(rename = "state")]
            state: String,
        },
        Err {
            #[serde(rename = "error")]
            error: String,
            #[serde(rename = "error_description")]
            error_description: Option<String>,
            #[serde(rename = "state")]
            state: Option<String>,
        },
    }

    fn handle_authorize_request(
        stream: &mut TcpStream,
        local_addr: SocketAddr,
    ) -> Result<AuthorizeResponse> {
        let result = {
            let mut reader = io::BufReader::new(&mut *stream);
            let mut request_line = String::new();
            io::BufRead::read_line(&mut reader, &mut request_line).inspect_err(|error| {
                error!(%error, "failed to read request line");
            })?;
            debug!(
                request_line = request_line.trim(),
                "daemon received request"
            );

            let path = request_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| Error::msg("malformed request line"))?;
            let url = Url::parse(&format!("http://{local_addr}{path}"))
                .map_err(|_| Error::msg("failed to parse callback URL"))?;
            let query = url.query().unwrap_or_default();
            serde_qs::from_str(query).map_err(|e| {
                error!(%e, query, "failed to deserialize query params");
                Error::ResponseError
            })
        };

        let response = match &result {
            Ok(AuthorizeResponse::Ok { .. }) => {
                let body = html_ok("Login");
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.as_bytes().len(),
                    body
                )
            }
            Ok(AuthorizeResponse::Err {
                error,
                error_description,
                ..
            }) => {
                let body = html_ko("Login", error, error_description.as_deref().unwrap_or(""));
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.as_bytes().len(),
                    body
                )
            }
            Err(_) => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".to_string(),
        };

        let _ = io::Write::write_all(stream, response.as_bytes());
        let _ = io::Write::flush(stream);

        result
    }

    pub fn launch_authorize() -> (
        mpsc::Receiver<Result<SocketAddr>>,
        mpsc::Receiver<Result<AuthorizeResponse>>,
        mpsc::SyncSender<()>,
    ) {
        launch(handle_authorize_request)
    }

    fn handle_logout_request(stream: &mut TcpStream, local_addr: SocketAddr) -> Result<()> {
        let result = {
            let mut reader = io::BufReader::new(&mut *stream);
            let mut request_line = String::new();
            io::BufRead::read_line(&mut reader, &mut request_line).inspect_err(|error| {
                error!(%error, "failed to read request line");
            })?;
            debug!(
                request_line = request_line.trim(),
                "daemon received request"
            );

            let path = request_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| Error::msg("malformed request line"))?;
            let url = Url::parse(&format!("http://{local_addr}{path}"))
                .map_err(|_| Error::msg("failed to parse callback URL"))?;
            let query = url.query().unwrap_or_default();
            println!("{query}");

            Ok(())
        };

        let response = match &result {
            Ok(_) => {
                let body = html_ok("Logout");
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.as_bytes().len(),
                    body
                )
            }
            Err(_) => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".to_string(),
        };

        let _ = io::Write::write_all(stream, response.as_bytes());
        let _ = io::Write::flush(stream);

        result
    }

    pub fn launch_logout() -> (
        mpsc::Receiver<Result<SocketAddr>>,
        mpsc::Receiver<Result<()>>,
        mpsc::SyncSender<()>,
    ) {
        launch(handle_logout_request)
    }

    fn launch<T, F>(
        handler: F,
    ) -> (
        mpsc::Receiver<Result<SocketAddr>>,
        mpsc::Receiver<Result<T>>,
        mpsc::SyncSender<()>,
    )
    where
        T: Send + 'static,
        F: Fn(&mut TcpStream, SocketAddr) -> Result<T> + Send + 'static,
    {
        let (local_addr_tx, local_addr_rx) = mpsc::sync_channel(1);
        let (code_tx, code_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);

        let _ = thread::spawn(move || {
            let _ = local_addr_tx;
            let _ = code_tx;

            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(x) => x,
                Err(error) => {
                    error!(%error, "failed to bind deamon to random port");
                    let _ = local_addr_tx.send(Err(Error::TcpListenerBind));
                    return;
                }
            };
            if let Err(error) = listener.set_nonblocking(true) {
                error!(%error, "failed to set deamon listener to non blocking");
                let _ = local_addr_tx.send(Err(Error::TcpListenerBind));
                return;
            }

            let local_addr = match listener.local_addr() {
                Ok(local_addr) => {
                    let _ = local_addr_tx.send(Ok(local_addr));
                    local_addr
                }
                Err(error) => {
                    error!(%error, "failed to set deamon listener to non blocking");
                    let _ = local_addr_tx.send(Err(Error::TcpListenerBind));
                    return;
                }
            };

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let _ = code_tx.send(handler(&mut stream, local_addr).map_err(|error| {
                            error!(%error, "failed to read incoming stream");
                            Error::ResponseError
                        }));

                        return;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if shutdown_rx.try_recv().is_ok() {
                            debug!("daemon received shutdown signal");
                            return;
                        }

                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(error) => {
                        error!(%error, "socket IO error");
                        let _ = code_tx.send(Err(Error::ResponseError));
                        return;
                    }
                }
            }
        });

        (local_addr_rx, code_rx, shutdown_tx)
    }

    // Most modern browsers prevent scripts from
    // closing windows they didn't open.
    fn html_ok(label: &str) -> String {
        formatdoc! {r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>{label} Successful</title>
                <style>
                    * {{
                        margin:0;
                        padding:0;
                        box-sizing:border-box
                    }}
                    body {{
                        font-family:-apple-system,system-ui,sans-serif;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        min-height:100vh;
                        background:#0f172a;
                        color:#e2e8f0
                    }}
                    div {{
                        text-align:center;
                        padding:2rem;
                        border-radius:1rem;
                        background:#1e293b;
                        box-shadow:0 4px 24px rgba(0,0,0,.3)
                    }}
                    h1 {{
                        font-size:1.5rem;
                        margin-bottom:.5rem;
                        color:#4ade80
                    }}
                    p {{
                        color:#94a3b8
                    }}
                </style>
            </head>
            <body>
                <div>
                    <h1>&#10003; {label} Successful</h1>
                    <p>You can now close this tab.</p>
                </div>
            </body>
            </html>
        "#}
    }

    fn html_ko(label: &str, error: &str, description: &str) -> String {
        formatdoc! {r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>{label} Failed</title>
                <style>
                    * {{
                        margin:0;
                        padding:0;
                        box-sizing:border-box
                    }}
                    body {{
                        font-family:-apple-system,system-ui,sans-serif;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        min-height:100vh;
                        background:#0f172a;
                        color:#e2e8f0
                    }}
                    div {{
                        text-align:center;
                        padding:2rem;
                        border-radius:1rem;
                        background:#1e293b;
                        box-shadow:0 4px 24px rgba(0,0,0,.3)
                    }}
                    h1 {{
                        font-size:1.5rem;
                        margin-bottom:.5rem;
                        color:#f87171
                    }}
                    p {{
                        color:#94a3b8;
                        margin-top:.5rem
                    }}
                    code {{
                        background:#0f172a;
                        padding:.15rem .4rem;
                        border-radius:.25rem;
                        font-size:.85rem
                    }}
                </style>
            </head>
            <body>
                <div>
                    <h1>&#10007; {label} Failed</h1>
                    <p><code>{error}</code></p>
                    <p>{description}</p>
                </div>
            </body>
            </html>
        "#}
    }
}
