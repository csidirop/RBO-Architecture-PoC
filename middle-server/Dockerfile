FROM php:8.3-apache

RUN a2enmod rewrite headers

COPY apache/poc.conf /etc/apache2/sites-available/000-default.conf
COPY public/ /var/www/html/public/
COPY templates/ /var/www/html/templates/

EXPOSE 80
