# Build context: repository root (see docker-compose files).
# Stage 1: the PortHub Go binary (private-network relay, later the gateway).
FROM golang:1.27 AS porthub
WORKDIR /src
COPY client/go.mod client/go.sum ./
RUN go mod download
COPY client/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/porthub ./cmd/porthub

# Stage 2: the API. constraints.txt pins every installed package to the
# versions already running in production so rebuilds never drift.
FROM python:3.10
WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH="/usr/lib/python3/dist-packages":$PYTHONPATH
COPY api/requirements.txt api/constraints.txt /app/
RUN pip install -r /app/requirements.txt -c /app/constraints.txt --no-cache-dir
COPY api/ /app/
# Outside /app so the source bind mount used in production does not hide it.
COPY --from=porthub /out/porthub /usr/local/bin/porthub

CMD chmod +x /app/entrypoint.sh && /app/entrypoint.sh
