FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54


RUN apt-get update && \
    apt-get install -y sqlite3 supervisor && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --home-dir /home/identity --create-home identity
RUN mkdir -p /home/identity/chall

COPY identityd securityd identity.db /home/identity/chall/

RUN chmod 555 /home/identity/chall/identityd /home/identity/chall/securityd && \
    chmod 600 /home/identity/chall/identity.db && \
    chown -R identity:identity /home/identity

WORKDIR /home/identity/chall

EXPOSE 5555

COPY supervisord.conf /etc/supervisor/supervisord.conf

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
