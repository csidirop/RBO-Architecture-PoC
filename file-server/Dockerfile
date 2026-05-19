FROM php:8.3-apache

RUN a2enmod headers rewrite

COPY apache/poc.conf /etc/apache2/sites-available/000-default.conf
COPY public/ /var/www/html/public/

EXPOSE 80
