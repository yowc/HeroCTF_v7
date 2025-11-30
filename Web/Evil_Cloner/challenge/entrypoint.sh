#!/bin/bash

while ! mysqladmin ping -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" --skip-ssl; do
    echo "Waiting for database connection..."
    sleep 1
done

node /usr/app/app.js