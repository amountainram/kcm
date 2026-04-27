use super::{AdminCliClient, handle_response, keycloak};
use crate::Result;
use tracing::error;
use ureq::http::header::AUTHORIZATION;

impl AdminCliClient {
    pub fn identity_provider_create(
        &mut self,
        realm: &str,
        body: keycloak::IdentityProviderRepresentation,
    ) -> Result<Option<String>> {
        let auth_header = self.authorize()?;

        let endpoint = self
            .api_endpoint(keycloak::paths::realms_realm_identity_provider_instances_post(realm));
        let res = self
            .agent
            .post(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .send_json(&body)
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res)?;

        Ok(body.alias)
    }
}
