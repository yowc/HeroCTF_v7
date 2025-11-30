# syntax=docker/dockerfile:1.7

############################
# Base deps (cache modules)
############################
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS deps
WORKDIR /src

COPY idp/go.mod idp/go.sum idp/
COPY sp/go.mod  sp/go.sum  sp/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    (cd idp && go mod download) && \
    (cd sp  && go mod download)

############################
# Build SP
############################
FROM deps AS build-sp
WORKDIR /src/sp
COPY sp/ .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/sp .

############################
# Build IDP
############################
FROM deps AS build-idp
WORKDIR /src/idp
COPY idp/ .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/idp .

############################
# Runtime SP
############################
FROM alpine:3.20 AS sp-runtime
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build-sp /out/sp /app/sp
RUN mkdir -p /app/data
EXPOSE 8080
ENTRYPOINT ["/app/sp"]

############################
# Runtime IDP
############################
FROM alpine:3.20 AS idp-runtime
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build-idp /out/idp /app/idp
RUN mkdir -p /app/data
EXPOSE 8081
ENTRYPOINT ["/app/idp"]
