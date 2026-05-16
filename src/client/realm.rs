use super::{AdminCliClient, as_json, handle_response, keycloak};
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

    pub fn realms_list(
        &mut self,
        page_size: u64,
        offset: u64,
        search: Option<&str>,
    ) -> Result<Vec<keycloak::RealmRepresentation>> {
        let auth_header = self.authorize()?;

        let endpoint = self.api_endpoint(keycloak::paths::realms_get());
        let res = self
            .agent
            .get(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        let realms = as_json::<Vec<keycloak::RealmRepresentation>>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint,
                "failed to deserialize list of users"
            );
        })?;

        if let Some(search) = search {
            Ok(realms
                .into_iter()
                .filter(|r| {
                    r.realm
                        .as_deref()
                        .map(|realm| realm.starts_with(search))
                        .unwrap_or_default()
                })
                .skip(offset as usize)
                .take(page_size as usize)
                .collect())
        } else {
            Ok(realms
                .into_iter()
                .skip(offset as usize)
                .take(page_size as usize)
                .collect())
        }
    }

    pub fn realms_list_hint(
        &mut self,
        page_size: u64,
        search: &str,
    ) -> Result<Vec<keycloak::RealmRepresentation>> {
        let auth_header = self.authorize()?;

        let endpoint = self.api_endpoint(keycloak::paths::realms_get());
        let res = self
            .agent
            .get(&endpoint)
            .query_pairs([("briefRepresentation", "true")])
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        let realms = as_json::<Vec<keycloak::RealmRepresentation>>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint,
                "failed to deserialize list of users"
            );
        })?;

        Ok(realms
            .into_iter()
            .filter(|r| {
                r.realm
                    .as_deref()
                    .map(|realm| realm.starts_with(search))
                    .unwrap_or_default()
            })
            .take(page_size as usize)
            .collect())
    }
}
