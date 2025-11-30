FROM openjdk:21-bookworm@sha256:f3c2871187043c46f1053dbdbba456032624c9e3e328e760e09e744710127a0b

WORKDIR /app

RUN apt-get update && apt-get install -y \
    postgresql \
    redis-server \
    nginx \
    clamav \
    supervisor

ENV NVM_DIR=/usr/local/nvm
ENV NODE_VERSION=24.7.0
RUN mkdir -p $NVM_DIR \
    && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default \
    && ln -s $NVM_DIR/versions/node/v$NODE_VERSION/bin/node /usr/local/bin/node \
    && ln -s $NVM_DIR/versions/node/v$NODE_VERSION/bin/npm /usr/local/bin/npm \
    && ln -s $NVM_DIR/versions/node/v$NODE_VERSION/bin/npx /usr/local/bin/npx

COPY ./conf/entrypoint.sh /entrypoint.sh
COPY ./conf/postgres_start.sh /postgres_start.sh
COPY ./conf/nginx.conf /etc/nginx/nginx.conf
COPY ./conf/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY ./conf/init.sql /app/init.sql

COPY ./backend/ /tmp/backend/
COPY ./frontend/ /tmp/frontend/

RUN useradd -ms /bin/bash app \
    && chown -R app:app /app \
    && chown postgres:postgres /postgres_start.sh \
    && chmod a+x /postgres_start.sh \
    && chmod a+x /entrypoint.sh \
    && freshclam \
    && cd /tmp/backend \
    && sh ./gradlew assemble \
    && cp ./build/libs/drive-0.0.1-SNAPSHOT.jar /app/app.jar \
    && rm -rf /tmp/backend/

RUN cd /tmp/frontend \
    && npm install \
    && npm run build \
    && rm -rf /usr/share/nginx/html/ \
    && cp -r ./build/ /usr/share/nginx/html/ \
    && chmod 777 /usr/share/nginx/html/ \
    && rm -rf /tmp/frontend/

EXPOSE 80
CMD ["/entrypoint.sh"]
