# The application is GPL-3.0; the original source and complete integration
# patches are linked in deploy/pairdrop/README.md.
FROM ghcr.io/schlagmichdoch/pairdrop:v1.11.2@sha256:c4b30977264a76e335740089e693a52a0d0d616330dec7f93c7b96beef7b4a02 AS upstream
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
WORKDIR /home/node/app
COPY deploy/pairdrop/package.json deploy/pairdrop/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=upstream /home/node/app/public ./public
COPY --from=upstream /home/node/app/server ./server
COPY deploy/pairdrop/licenses ./public/licenses
COPY --from=upstream /home/node/app/LICENSE ./LICENSE
COPY deploy/pairdrop/patch.cjs /opt/porthub-pairdrop-patch.cjs
RUN node /opt/porthub-pairdrop-patch.cjs /home/node/app
COPY deploy/pairdrop/porthub.js /home/node/app/public/scripts/porthub.js
COPY deploy/pairdrop/rtc.json /home/node/app/porthub-rtc.json
ENV NODE_ENV=production WS_FALLBACK=true RTC_CONFIG=/home/node/app/porthub-rtc.json DEBUG_MODE=false RATE_LIMIT=1
LABEL io.porthub.pairdrop-source=4862ba3067be1a0f2e0d1e94861dc9200b5bfeea
USER 10001:10001
ENTRYPOINT ["node", "server/index.js"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "require('http').get('http://127.0.0.1:3000/config',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
