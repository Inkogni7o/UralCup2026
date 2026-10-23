FROM php:8.2-cli
RUN docker-php-ext-install pdo_mysql
WORKDIR /app
COPY . .
RUN php -l jwt.php \
    && php -l remember.php \
    && php -l report.php \
    && php tests/security.php
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "public", "router.php"]
