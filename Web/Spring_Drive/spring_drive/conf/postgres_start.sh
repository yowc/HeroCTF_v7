#!/bin/bash
set -e

POSTGRES_DATA="/var/lib/postgresql/data"

POSTGRES_USER="pguser"
POSTGRES_PASSWORD="password"
POSTGRES_DB="db"


if [ ! -s "$POSTGRES_DATA/PG_VERSION" ]; then
    /usr/lib/postgresql/15/bin/initdb -D "$POSTGRES_DATA"
    /usr/lib/postgresql/15/bin/pg_ctl -D "$POSTGRES_DATA" -w start

    psql --username=postgres <<-EOSQL
        CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';
        CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;
EOSQL

    psql --username=$POSTGRES_USER --dbname=$POSTGRES_DB -f /app/init.sql
    /usr/lib/postgresql/15/bin/pg_ctl -D "$POSTGRES_DATA" -m fast -w stop
fi

/usr/lib/postgresql/15/bin/postgres -D "$POSTGRES_DATA"
