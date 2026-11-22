# node:24-bookworm-slim. Digest pinned so the base image cannot move under the tag.
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @bitwarden/cli@2026.10.0 \
 && mkdir -p /app /data /data/home \
 && chown -R node:node /app /data

WORKDIR /app
COPY --chown=node:node server.mjs /app/server.mjs
COPY --chown=node:node deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh

# Inside the container the process must listen on 0.0.0.0 or Docker's published
# port never reaches it. On the host, publish 127.0.0.1:8788:8788 (see the
# compose files). Do not publish 0.0.0.0:8788.
ENV SECRETS_BROKER_HOME=/data \
    SECRETS_BROKER_PORT=8788 \
    SECRETS_BROKER_BIND=0.0.0.0 \
    SECRETS_BROKER_BW=/usr/local/lib/node_modules/@bitwarden/cli/build/bw.js \
    HOME=/data/home

VOLUME ["/data"]
EXPOSE 8788

USER node
ENTRYPOINT ["/app/entrypoint.sh"]
