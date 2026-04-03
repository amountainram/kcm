#!/bin/sh

/opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080/ \
    --realm master \
    --user ${KC_BOOTSTRAP_ADMIN_USERNAME} \
    --password ${KC_BOOTSTRAP_ADMIN_PASSWORD};
/opt/keycloak/bin/kcadm.sh get http://localhost:9000/health;
