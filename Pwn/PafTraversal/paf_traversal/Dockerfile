# => BUILDER
FROM golang:1.25-trixie@sha256:a02d35efc036053fdf0da8c15919276bf777a80cbfda6a35c5e9f087e652adfc AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential make ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY ./api/ ./api/
COPY ./cracker/ ./cracker/

# Build the Go binary
WORKDIR /src/api/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o api .

# Build the C binary
WORKDIR /src/cracker
RUN make

# => RUNTIME
FROM debian:trixie@sha256:8f6a88feef3ed01a300dafb87f208977f39dccda1fd120e878129463f7fa3b8f AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m app -d /app/

COPY ./entrypoint.sh /entrypoint.sh
# COPY --from=builder /src/api/ /app/api/
# COPY --from=builder /src/cracker/ /app/cracker/
COPY ./api/ /app/api/
COPY ./cracker/ /app/cracker/

RUN chmod +x /entrypoint.sh && \
    chown app:app -R /app/

USER app
WORKDIR /app/

CMD ["/entrypoint.sh"]