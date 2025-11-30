FROM python:3.13-alpine

RUN apk --update add socat \
	&& adduser -D --home /app user \
	&& pip install fickling picklescan

COPY --chown=user chall.py entry.sh flag.txt /app

RUN chmod 755 /app/entry.sh /app/chall.py

EXPOSE ${LISTEN_PORT}

ENTRYPOINT ["/app/entry.sh"]

