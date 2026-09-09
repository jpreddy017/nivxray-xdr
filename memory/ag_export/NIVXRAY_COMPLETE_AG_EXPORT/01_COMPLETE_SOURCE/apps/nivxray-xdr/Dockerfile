# ─────────────────────────────────────────────────────────────
# NivXRay XDR — standalone frontend build
#
# Builds ONLY this package.  Never builds `/app/frontend` (the base
# NivXRay application) and never adds a second backend / SSOT / engine.
# Runtime consumes the existing NivXRay platform via authenticated
# HTTP APIs.
# ─────────────────────────────────────────────────────────────

# ── Stage 1 · build ─────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

# Install deps first for cache-friendliness.
COPY package.json yarn.lock ./
RUN corepack enable && yarn install --frozen-lockfile

# Copy source and build the static bundle.
COPY vite.config.js index.html ./
COPY src ./src
# The API URL is read from `REACT_APP_NIVXRAY_API_URL` (or, as a
# fallback, `REACT_APP_BACKEND_URL`) at build time and inlined into
# the JS bundle via Vite `define`.  Set it as a build-arg so a single
# image is reproducible per environment.
ARG REACT_APP_NIVXRAY_API_URL=""
ENV REACT_APP_NIVXRAY_API_URL=$REACT_APP_NIVXRAY_API_URL
RUN yarn build

# ── Stage 2 · serve ─────────────────────────────────────────────
# nginx:alpine — small static image with an SPA history-fallback
# rule so any client-side route resolves to index.html.
FROM nginx:1.27-alpine

# SPA history-fallback + cache-control for hashed assets.
RUN printf '%s\n' \
    'server {' \
    '  listen 80 default_server;' \
    '  server_name _;' \
    '  root /usr/share/nginx/html;' \
    '  index index.html;' \
    '  # Hashed assets — long-cache immutable.' \
    '  location /assets/ {' \
    '    add_header Cache-Control "public, max-age=31536000, immutable";' \
    '    try_files $uri =404;' \
    '  }' \
    '  # Everything else falls back to the SPA entry.' \
    '  location / {' \
    '    add_header Cache-Control "no-cache";' \
    '    try_files $uri /index.html;' \
    '  }' \
    '}' > /etc/nginx/conf.d/default.conf

COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
