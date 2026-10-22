# PortHub server: one container with everything (API, UI, database, web
# proxy, tunnel server, firewall, private-network relay) supervised by the
# porthub binary. Runs with host networking; internal services bind to
# 127.0.0.1. Build context: repository root.

FROM golang:1.27 AS porthub
WORKDIR /src
COPY client/go.mod client/go.sum ./
RUN go mod download
COPY client/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/porthub ./cmd/porthub

FROM golang:1.27 AS server
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
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

# Python packages built with the full toolchain, run on the slim image.
FROM python:3.10 AS python
COPY api/requirements.txt /tmp/req/api.txt
COPY api/constraints.txt /tmp/req/constraints.txt
COPY firewall/requirements.txt /tmp/req/firewall.txt
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r /tmp/req/api.txt -r /tmp/req/firewall.txt -c /tmp/req/constraints.txt

FROM python:3.10-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends nftables libcurl4t64 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=python /opt/venv /opt/venv
COPY --from=porthub /out/porthub /usr/local/bin/porthub
COPY --from=server /out/porthub-api /usr/local/bin/porthub-api
COPY --from=mongo /usr/bin/mongod /usr/bin/mongodump /usr/bin/mongorestore /usr/local/bin/
COPY --from=traefik /usr/local/bin/traefik /usr/local/bin/traefik
COPY --from=rathole /rathole /usr/local/bin/rathole
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# Next.js standalone server: only the traced modules, plus static assets.
COPY --from=ui /app/.next/standalone /app/ui/
COPY --from=ui /app/.next/static /app/ui/.next/static
COPY --from=ui /app/public /app/ui/public
COPY api/ /app/api/
COPY firewall/ /app/firewall/
COPY traefik/internal.yml /app/traefik/internal.yml
COPY proxy/certificate/ /app/traefik/certificate/
COPY deploy/ /app/deploy/
VOLUME ["/data"]
ENTRYPOINT ["/bin/sh", "/app/deploy/entrypoint.sh"]
