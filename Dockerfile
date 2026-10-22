# PortHub server: one container with everything (API, UI, database, web
# proxy, tunnel server, firewall, private-network relay) supervised by the
# porthub binary. Runs with host networking; internal services bind to
# 127.0.0.1. Build context: repository root.

FROM golang:1.27 AS porthub
WORKDIR /src
COPY client/go.mod client/go.sum ./
RUN go mod download
COPY client/ ./
ARG PORTHUB_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$PORTHUB_VERSION" -o /out/porthub ./cmd/porthub
# Client binaries for every supported machine, served by the API
# (/api/downloads/porthub/<target>); also the drop-in tunnel client.
RUN set -e; mkdir -p /out/client-bin; \
    for t in x86_64,linux,amd64,0 arm64,linux,arm64,0 armv7,linux,arm,7 armhf,linux,arm,6 \
             darwin_x86_64,darwin,amd64,0 darwin_arm64,darwin,arm64,0; do \
      set -- $(echo "$t" | tr , ' '); \
      CGO_ENABLED=0 GOOS=$2 GOARCH=$3 GOARM=$4 go build -trimpath -ldflags "-s -w -X main.version=$PORTHUB_VERSION" \
        -o /out/client-bin/porthub-$1 ./cmd/porthub; \
      echo "$PORTHUB_VERSION" > /out/client-bin/porthub-$1.version; \
    done

FROM golang:1.27 AS api
WORKDIR /src
COPY api/go.mod api/go.sum ./
RUN go mod download
COPY api/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/porthub-api ./cmd/porthub-api

FROM node:19.8.1-slim AS ui
WORKDIR /app
COPY ui/package.json ui/yarn.lock ./
RUN yarn install --frozen-lockfile
COPY ui/ ./
RUN yarn build

FROM mongo:7.0 AS mongo
FROM traefik:v3.0 AS traefik
FROM archef2000/rathole:latest AS rathole
FROM node:19.8.1-slim AS node

# nft 1.1 (trixie): bookworm's 1.0.6 segfaults on the firewall ruleset.
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends nftables libcurl4t64 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=porthub /out/porthub /usr/local/bin/porthub
COPY --from=porthub /out/client-bin /app/client-bin
COPY --from=api /out/porthub-api /usr/local/bin/porthub-api
COPY --from=mongo /usr/bin/mongod /usr/bin/mongodump /usr/bin/mongorestore /usr/local/bin/
COPY --from=traefik /usr/local/bin/traefik /usr/local/bin/traefik
COPY --from=rathole /rathole /usr/local/bin/rathole
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# Next.js standalone server: only the traced modules, plus static assets.
COPY --from=ui /app/.next/standalone /app/ui/
COPY --from=ui /app/.next/static /app/ui/.next/static
COPY --from=ui /app/public /app/ui/public
COPY api/assets/client/ /app/client/
COPY deploy/ /app/deploy/
VOLUME ["/data"]
ENTRYPOINT ["/bin/sh", "/app/deploy/entrypoint.sh"]
