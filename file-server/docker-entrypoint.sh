#!/bin/sh
set -eu

envsubst \
  '${OIDC_CRYPTO_PASSPHRASE} ${FILE_TOKEN_SECRET} ${FILE_TOKEN_ISSUER} ${FILE_TOKEN_AUDIENCE}' \
  < /usr/local/share/apache2/poc.conf.template \
  > /etc/apache2/sites-available/000-default.conf

exec "$@"
