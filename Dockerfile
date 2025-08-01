FROM php:8.1-apache

# Install required extensions and system packages
RUN apt-get update && apt-get install -y \
    cron \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    curl \
    git \
    libzip-dev \
    libldap2-dev \
    libicu-dev \
    libcurl4-openssl-dev \
    libpq-dev \
    libmcrypt-dev \
    libssl-dev \
    libc-client-dev \
    libkrb5-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install pdo pdo_mysql mysqli mbstring zip exif pcntl bcmath gd ldap intl soap imap

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set PHP configuration using environment variables
ARG SUITECRM_MEMORY_LIMIT=256M
ARG SUITECRM_UPLOAD_MAX_FILESIZE=20M
ARG SUITECRM_POST_MAX_SIZE=25M

RUN echo "memory_limit = ${SUITECRM_MEMORY_LIMIT}" > /usr/local/etc/php/conf.d/memory.ini && \
    echo "upload_max_filesize = ${SUITECRM_UPLOAD_MAX_FILESIZE}" > /usr/local/etc/php/conf.d/uploads.ini && \
    echo "post_max_size = ${SUITECRM_POST_MAX_SIZE}" > /usr/local/etc/php/conf.d/post.ini && \
    echo "max_execution_time = 300" > /usr/local/etc/php/conf.d/timeout.ini && \
    echo "error_reporting = E_ALL & ~E_DEPRECATED & ~E_NOTICE" > /usr/local/etc/php/conf.d/error_reporting.ini && \
    echo "display_errors = Off" >> /usr/local/etc/php/conf.d/error_reporting.ini

# Set working directory
WORKDIR /var/www/html
RUN chown -R www-data:www-data /var/www/html
