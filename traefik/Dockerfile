FROM traefik:v3.0
COPY entrypoint.sh /porthub-entrypoint.sh
COPY internal.yml /porthub/internal.yml
ENTRYPOINT ["/bin/sh", "/porthub-entrypoint.sh"]
