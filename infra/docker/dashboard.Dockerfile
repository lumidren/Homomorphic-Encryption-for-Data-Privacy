# syntax=docker/dockerfile:1.7
#   docker build -f infra/docker/dashboard.Dockerfile -t ciphercompute-dashboard .
# Next.js "standalone" output: the runtime image contains only the traced server files.

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-bookworm-slim AS deps
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:${NODE_VERSION}-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY dashboard/ ./
RUN npm run build

FROM node:${NODE_VERSION}-bookworm-slim AS runtime
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="ciphercompute-dashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/lumidren/Homomorphic-Encryption-for-Data-Privacy" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app
COPY --from=build --chown=app:app /app/.next/standalone ./
COPY --from=build --chown=app:app /app/.next/static ./.next/static
USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
