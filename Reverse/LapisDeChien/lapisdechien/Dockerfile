FROM openresty/openresty:alpine-fat@sha256:697ddbb6be93195519791332e93d3523fb0e8576b714684cfd4773fef54a7314 AS builder

WORKDIR /usr/local/openresty/nginx/lua/

RUN apk add --no-cache \
    bash findutils sqlite sqlite-dev \
    git wget curl ca-certificates \
    lua5.1 build-base openssl-dev pcre-dev zlib-dev && \
    luarocks install lapis && \
    luarocks install luafilesystem && \
    luarocks install lsqlite3

COPY ./conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY ./conf/entrypoint.sh /entrypoint.sh
COPY ./dist/ /usr/local/openresty/nginx/lua/

RUN chown -R nobody:nobody /usr/local/openresty/nginx/lua/public/ && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]