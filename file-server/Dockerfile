FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libapache2-mod-auth-openidc \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite headers auth_openidc

COPY file-server/apache/poc.conf /etc/apache2/sites-available/000-default.conf
COPY file-server/public/ /var/www/html/public/
COPY token-keys/file-token-public.crt /etc/apache2/file-token-public.crt

EXPOSE 80
