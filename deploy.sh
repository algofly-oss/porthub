docker compose -f docker-compose-prod.yml build --parallel && \
docker compose -f docker-compose-prod.yml down -t 0 && \
docker compose -f docker-compose-prod.yml up -d &&
docker compose -f docker-compose-prod.yml logs -f