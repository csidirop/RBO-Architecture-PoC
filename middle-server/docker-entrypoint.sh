#!/bin/sh
set -eu

envsubst \
  '${APP_BASE_URL} ${KEYCLOAK_INTERNAL_BASE_URL} ${KEYCLOAK_REALM} ${KEYCLOAK_CLIENT_ID} ${KEYCLOAK_CLIENT_SECRET} ${OIDC_CRYPTO_PASSPHRASE}' \
  < /usr/local/share/apache2/poc.conf.template \
  > /etc/apache2/sites-available/000-default.conf

exec "$@"
