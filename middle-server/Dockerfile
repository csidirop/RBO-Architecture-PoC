FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends gettext-base libapache2-mod-auth-openidc \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod auth_openidc rewrite headers proxy proxy_http

RUN printf '\nListen 8080\n' >> /etc/apache2/ports.conf

COPY apache/poc.conf.template /usr/local/share/apache2/poc.conf.template
COPY docker-entrypoint.sh /usr/local/bin/middle-entrypoint.sh
COPY public/ /var/www/html/public/
COPY templates/ /var/www/html/templates/

RUN chmod +x /usr/local/bin/middle-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/middle-entrypoint.sh"]
CMD ["apache2-foreground"]

EXPOSE 80
