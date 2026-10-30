# syntax=docker/dockerfile:1.7
# Independent slim runtime images; one Compose file chooses prod/dev targets.
ARG PORTHUB_CORE_ARTIFACT_SOURCE=rust-build
FROM rust:1.99.1-slim-bookworm AS rust-build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY vendor/ vendor/
ARG PORTHUB_VERSION=1.8.5
ARG PORTHUB_BUILD_JOBS=4
ARG PORTHUB_SOURCE_REVISION=unknown
ENV PORTHUB_SOURCE_REVISION=$PORTHUB_SOURCE_REVISION
ENV PORTHUB_VERSION=$PORTHUB_VERSION RUST_MIN_STACK=33554432 CARGO_BUILD_JOBS=$PORTHUB_BUILD_JOBS
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    cargo build --locked --release -p porthub-api -p porthub-edge -p porthub-firewall -p porthub-runtime && mkdir -p /out && \
    cp target/release/porthub-api target/release/porthub-edge \
       target/release/porthub-firewall target/release/porthub-runtime /out/ && \
    cp /out/porthub-api /out/porthub-runtime /usr/local/bin/

# Agents run on hosts with different libc versions. Native musl builds provide
# one self-contained Linux executable without a distribution-specific loader.
FROM rust:1.99.1-alpine AS agent-build
WORKDIR /src
RUN apk add --no-cache build-base
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY vendor/ vendor/
ARG PORTHUB_VERSION=1.8.5
ARG PORTHUB_BUILD_JOBS=4
ARG TARGETARCH
ARG PORTHUB_SOURCE_REVISION=unknown
ENV PORTHUB_SOURCE_REVISION=$PORTHUB_SOURCE_REVISION
ENV PORTHUB_VERSION=$PORTHUB_VERSION RUST_MIN_STACK=33554432 CARGO_BUILD_JOBS=$PORTHUB_BUILD_JOBS
RUN --mount=type=cache,id=porthub-agent-musl-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=porthub-agent-musl-target,target=/src/target \
    cargo build --locked --release -p porthub-agent --bin porthub && \
    target/release/porthub version && \
    readelf -l target/release/porthub > /tmp/porthub-elf && \
    if grep -q INTERP /tmp/porthub-elf; then echo 'Agent must not require a dynamic loader' >&2; exit 1; fi && \
    mkdir -p /out/client-bin && \
    case "$TARGETARCH" in amd64) agent_target=x86_64 ;; arm64) agent_target=arm64 ;; *) exit 1 ;; esac && \
    cp target/release/porthub /out/client-bin/porthub-$agent_target && \
    cd /out/client-bin && sha256sum porthub-$agent_target > porthub-$agent_target.sha256 && \
    echo "$PORTHUB_VERSION" > /out/client-bin/porthub-$agent_target.version

FROM scratch AS agent-artifacts
COPY --from=agent-build /out/client-bin/ /

FROM node:22-bookworm-slim AS ui-build
WORKDIR /src/ui
COPY ui/package.json ui/yarn.lock ./
RUN --mount=type=cache,id=porthub-ui-yarn,target=/usr/local/share/.cache/yarn,sharing=locked \
    corepack enable && yarn install --frozen-lockfile --network-timeout 120000 --network-concurrency 4
COPY ui/ ./
RUN yarn build && yarn next export --outdir /out/ui && \
    find /out/ui -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' -o -name '*.json' -o -name '*.svg' \) -exec gzip --keep -9 {} +

FROM mongo:7.0 AS database
FROM node:22-bookworm-slim AS node-runtime

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    printf 'porthub:x:10001:10001:PortHub:/nonexistent:/usr/sbin/nologin\n' >> /etc/passwd && \
    printf 'porthub:x:10001:\n' >> /etc/group
ARG PORTHUB_VERSION=1.8.5
ENV RUST_LOG=info PORTHUB_VERSION=$PORTHUB_VERSION
LABEL org.opencontainers.image.version=$PORTHUB_VERSION
ARG PORTHUB_SOURCE_REVISION=unknown
LABEL org.opencontainers.image.revision=$PORTHUB_SOURCE_REVISION

# UI-only builds can reuse matching, already verified core artifacts. Building
# from runtime-base keeps old UI assets out of the final image's layer history.
FROM ${PORTHUB_CORE_ARTIFACT_SOURCE} AS core-artifacts

FROM runtime-base AS core-runtime
LABEL io.porthub.api-preflight=v1
RUN apt-get update && apt-get install -y --no-install-recommends libcurl4 libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data/mongo /run/porthub-api /run/porthub-edge /run/porthub-firewall /run/porthub-config /run/porthub-activity /app/ui && \
    chown -R 10001:10001 /data /run/porthub-api /run/porthub-edge /run/porthub-firewall /run/porthub-config /run/porthub-activity /app && \
    chmod 0750 /run/porthub-api /run/porthub-config && chmod 0770 /run/porthub-edge /run/porthub-firewall /run/porthub-activity && \
    printf '[server.services]\n' > /run/porthub-config/gateway.toml && \
    chown 10001:10001 /run/porthub-config/gateway.toml
COPY --from=core-artifacts /usr/local/bin/porthub-api /usr/local/bin/porthub-runtime /usr/local/bin/
COPY --from=database /usr/bin/mongod /usr/local/bin/mongod
COPY --from=ui-build --chown=10001:10001 /out/ui /app/ui/
COPY deploy/native/core.toml /app/core.toml
USER 10001:10001
ENTRYPOINT ["porthub-runtime", "supervise", "--config", "/app/core.toml"]

FROM core-runtime AS prod-core
LABEL io.porthub.agent-distribution=github-cache-v1

FROM core-runtime AS dev-core
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev pkg-config libssl-dev libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=rust-build /src /src
COPY --from=rust-build /usr/local/cargo /usr/local/cargo
COPY --from=rust-build /usr/local/rustup /usr/local/rustup
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=ui-build --chown=10001:10001 /src/ui /app/ui-dev
ENV CARGO_HOME=/opt/porthub-cargo CARGO_TARGET_DIR=/src/target RUSTUP_HOME=/usr/local/rustup \
    PATH=/src/target/release:/usr/local/cargo/bin:$PATH
RUN mkdir -p /opt/porthub-cargo /src/target && \
    chown -R 10001:10001 /opt/porthub-cargo /src/target /data /run/porthub-api \
      /run/porthub-edge /run/porthub-firewall /run/porthub-config /run/porthub-activity /app
USER 10001:10001

FROM runtime-base AS prod-edge
RUN mkdir -p /run/porthub-api /run/porthub-edge /run/porthub-config /run/porthub-activity /data/certificates && \
    chown 10001:10001 /run/porthub-api /run/porthub-config /run/porthub-activity && \
    chown 0:10001 /run/porthub-edge && \
    chmod 0750 /run/porthub-api /run/porthub-config && chmod 0770 /run/porthub-edge /run/porthub-activity && \
    chown -R 0:10001 /data/certificates && chmod 0770 /data/certificates
COPY --from=rust-build /out/porthub-edge /out/porthub-runtime /usr/local/bin/
# Only NET_BIND_SERVICE is granted by Compose; no database or firewall access.
USER 0:10001
ENTRYPOINT ["porthub-edge", "--config", "/run/porthub-config/gateway.toml"]

FROM prod-edge AS dev-edge
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev pkg-config libssl-dev libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=rust-build /src /src
COPY --from=rust-build /usr/local/cargo /usr/local/cargo
COPY --from=rust-build /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/opt/porthub-cargo CARGO_TARGET_DIR=/src/target RUSTUP_HOME=/usr/local/rustup \
    PATH=/src/target/release:/usr/local/cargo/bin:$PATH
RUN mkdir -p /opt/porthub-cargo /src/target && \
    chown -R 0:10001 /opt/porthub-cargo /src/target && \
    chmod -R g+rwX /opt/porthub-cargo /src/target
USER 0:10001
ENTRYPOINT ["cargo", "run", "--locked", "-p", "porthub-edge", "--", "--config", "/run/porthub-config/gateway.toml"]

FROM runtime-base AS prod-firewall
RUN mkdir -p /data/firewall /run/porthub-firewall && \
    chown -R 0:10001 /data/firewall /run/porthub-firewall && chmod 0770 /run/porthub-firewall
COPY --from=rust-build /out/porthub-firewall /out/porthub-runtime /usr/local/bin/
# Root UID with only NET_ADMIN: non-root exec loses this capability on Docker.
USER 0:10001
ENTRYPOINT ["porthub-firewall"]

FROM prod-firewall AS dev-firewall
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev pkg-config libssl-dev libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=rust-build /src /src
COPY --from=rust-build /usr/local/cargo /usr/local/cargo
COPY --from=rust-build /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/opt/porthub-cargo CARGO_TARGET_DIR=/src/target RUSTUP_HOME=/usr/local/rustup \
    PATH=/src/target/release:/usr/local/cargo/bin:$PATH
RUN mkdir -p /opt/porthub-cargo /src/target && \
    chown -R 0:10001 /opt/porthub-cargo /src/target && \
    chmod -R g+rwX /opt/porthub-cargo /src/target
USER 0:10001
ENTRYPOINT ["cargo", "run", "--locked", "-p", "porthub-firewall"]
