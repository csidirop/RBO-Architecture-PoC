FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends gettext-base libapache2-mod-auth-openidc \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod auth_openidc headers rewrite

COPY apache/poc.conf.template /usr/local/share/apache2/poc.conf.template
COPY docker-entrypoint.sh /usr/local/bin/file-server-entrypoint.sh
COPY public/ /var/www/html/public/

RUN chmod +x /usr/local/bin/file-server-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/file-server-entrypoint.sh"]
CMD ["apache2-foreground"]

EXPOSE 80
