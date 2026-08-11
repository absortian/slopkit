# syntax=docker/dockerfile:1.6
# ---------------------------------------------------------------------------
# Stage 1 — build the static web-server image (slopkit content).
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS web

WORKDIR /srv

# Copy the whole repo (static assets + payloads + offsets + slopkit + ui).
COPY . /srv

# http.server is fine for this — payloads are streamed over a separate TCP
# channel (127.0.0.1:9021) by elfldr, not through HTTP.
EXPOSE 8080
CMD ["python", "-u", "-m", "http.server", "8080", "--bind", "0.0.0.0"]

# ---------------------------------------------------------------------------
# Stage 2 — build the minimal captive-port DNS server (scratch + Go).
# Single A record: manuals.playstation.net -> DNS_IP (env var).
# ---------------------------------------------------------------------------
FROM golang:1.22-alpine AS dns-builder

WORKDIR /src
COPY dns/ /src/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dns ./...

FROM scratch AS dns
COPY --from=dns-builder /out/dns /dns
# scratch has no shell. EXPOSE is documentation only — docker-compose's
# `ports:` does the actual host-side binding.
ENV DNS_IP=127.0.0.1
EXPOSE 53/udp
ENTRYPOINT ["/dns"]