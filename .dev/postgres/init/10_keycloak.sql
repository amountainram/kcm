-- run as superuser

do $$
begin
    if not exists (
        select from pg_catalog.pg_roles where rolname = 'keycloak_user'
    ) then
        create user keycloak_user;
    end if;
end
$$;

select 'CREATE DATABASE keycloak OWNER keycloak_user'
where not exists (
    select from pg_catalog.pg_database
    where datname = 'keycloak'
)\gexec