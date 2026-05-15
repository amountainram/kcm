use super::{AdminCliClient, as_json, handle_response, keycloak};
use crate::{Error, Result};
use tracing::error;
use ureq::http::header::AUTHORIZATION;

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
        body: keycloak::ClientRepresentation,
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
            .and_then(|keycloak::ClientRepresentation { id, .. }| id)
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

    pub fn clients_list_hint(
        &mut self,
        realm: &str,
        page_size: u64,
        search: &str,
    ) -> Result<Vec<keycloak::ClientRepresentation>> {
        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_clients_get(realm));

        let mut query = vec![
            ("max", page_size.to_string()),
            ("first", 0.to_string()),
        ];
        if !search.is_empty() {
            query.push(("clientId", search.to_string()));
            query.push(("search", "true".to_string()));
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
}
