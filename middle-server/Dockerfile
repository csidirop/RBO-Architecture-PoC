FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libapache2-mod-auth-openidc \
    && rm -rf /var/lib/apt/lists/*
RUN a2enmod rewrite headers proxy proxy_http auth_openidc

COPY middle-server/apache/poc.conf /etc/apache2/sites-available/000-default.conf
COPY middle-server/public/ /var/www/html/public/
COPY middle-server/templates/ /var/www/html/templates/
COPY token-keys/file-token-private.pem /run/secrets/file-token-private.pem
RUN chown www-data:www-data /run/secrets/file-token-private.pem \
    && chmod 640 /run/secrets/file-token-private.pem

EXPOSE 80
