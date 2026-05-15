use super::{AdminCliClient, as_json, handle_response, keycloak};
use crate::{Error, Result};
use tracing::error;
use ureq::http::header::AUTHORIZATION;

impl AdminCliClient {
    pub fn users_list(
        &mut self,
        realm: &str,
        page_size: u64,
        offset: u64,
        search: Option<&str>,
        exact: bool,
    ) -> Result<Vec<keycloak::UserRepresentation>> {
        let auth_header = self.authorize()?;

        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_users_get(realm));
        let mut query = vec![
            ("max", page_size.to_string()),
            ("first", offset.to_string()),
        ];
        if let Some(search) = search {
            query.push(("search", search.to_string()));
            query.push(("exact", exact.to_string()));
        }
        let res = self
            .agent
            .get(&endpoint)
            .query_pairs(query)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        as_json::<Vec<keycloak::UserRepresentation>>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint,
                "failed to deserialize list of users"
            );
        })
    }

    pub fn users_list_hint(
        &mut self,
        realm: &str,
        page_size: u64,
        search: &str,
    ) -> Result<Vec<keycloak::UserRepresentation>> {
        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_users_get(realm));

        let query = vec![
            ("max", page_size.to_string()),
            ("first", 0.to_string()),
            ("briefRepresentation", "true".to_string()),
            ("search", search.to_string()),
            ("exact", "false".to_string()),
        ];
        let res = self
            .agent
            .get(&endpoint)
            .query_pairs(query)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        let users = as_json::<Vec<keycloak::UserRepresentation>>(res).inspect_err(|error| {
            error!(
                %error,
                endpoint,
                "failed to deserialize list of users"
            );
        })?;
        Ok(users
            .into_iter()
            .filter(|u| {
                !u.username
                    .as_deref()
                    .unwrap_or("")
                    .starts_with("service-account-")
            })
            .collect())
    }

    pub fn user_describe(
        &mut self,
        realm: &str,
        username: &str,
    ) -> Result<Option<keycloak::UserRepresentation>> {
        Ok(self.users_list(realm, 1, 0, Some(username), true)?.pop())
    }

    pub fn user_create(
        &mut self,
        realm: &str,
        body: keycloak::UserRepresentation,
    ) -> Result<Option<String>> {
        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_users_post(realm));

        let res = self
            .agent
            .post(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .send_json(&body)
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res).map_err(|error| {
            error!(%error, "failed to delete client");
            Error::Conflict
        })?;

        Ok(body.id)
    }

    pub fn role_get(
        &mut self,
        realm: &str,
        role_name: &str,
    ) -> Result<keycloak::RoleRepresentation> {
        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_roles_role_name_get(
            realm, role_name,
        ));
        let res = self
            .agent
            .get(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .call()
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        let res = handle_response(res)?;
        as_json(res)
    }

    pub fn user_assign_realm_roles(
        &mut self,
        realm: &str,
        user_id: &str,
        roles: Vec<keycloak::RoleRepresentation>,
    ) -> Result<()> {
        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(
            keycloak::paths::realms_realm_users_user_id_role_mappings_realm_post(realm, user_id),
        );
        let res = self
            .agent
            .post(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .send_json(&roles)
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res)?;
        Ok(())
    }

    pub fn user_set_activation(
        &mut self,
        realm: &str,
        username: &str,
        enabled: bool,
    ) -> Result<()> {
        let user = self
            .user_describe(realm, username)?
            .ok_or(Error::NotFound)?;
        let user_id = user.id.as_deref().ok_or(Error::NotFound)?;

        let auth_header = self.authorize()?;
        let endpoint = self.api_endpoint(keycloak::paths::realms_realm_users_user_id_put(
            realm, user_id,
        ));
        let body = keycloak::UserRepresentation {
            enabled: Some(enabled),
            ..Default::default()
        };
        let res = self
            .agent
            .put(&endpoint)
            .header(AUTHORIZATION, auth_header)
            .send_json(&body)
            .inspect_err(|error| error!(%error, endpoint, "http failure"))?;
        handle_response(res)?;

        Ok(())
    }
}
