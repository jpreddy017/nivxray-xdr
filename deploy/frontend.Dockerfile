# ─────────────────────────────────────────────────────────────
# NivXRay XDR · Frontend production image (P0-F · Sprint 1)
# Build the React SPA, serve with nginx.  SPA history-fallback.
# ─────────────────────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app

# Deps first for cache-friendliness.
COPY frontend/package.json frontend/yarn.lock ./
RUN corepack enable && yarn install --frozen-lockfile

# Source + build.
COPY frontend/ ./
ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
RUN yarn build


# ── Stage 2 · serve ─────────────────────────────────────────────
FROM nginx:1.27-alpine

RUN printf '%s\n' \
    'server {' \
    '  listen 80 default_server;' \
    '  server_name _;' \
    '  root /usr/share/nginx/html;' \
    '  index index.html;' \
    '  # Static hashed assets — long cache.' \
    '  location /static/ {' \
    '    add_header Cache-Control "public, max-age=31536000, immutable";' \
    '    try_files $uri =404;' \
    '  }' \
    '  # SPA history-fallback.' \
    '  location / {' \
    '    add_header Cache-Control "no-cache";' \
    '    try_files $uri /index.html;' \
    '  }' \
    '}' > /etc/nginx/conf.d/default.conf

COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
