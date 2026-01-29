FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      openssl \
      freeradius \
      freeradius-postgresql \
      freeradius-utils \
      postgresql-client \
      iproute2 \
      net-tools \
    && rm -rf /var/lib/apt/lists/*

# Our overlay config: keep the distro defaults, but replace the parts we need (sql + central policy).
COPY etc/freeradius/3.0/ /etc/freeradius/3.0/
COPY entrypoint.sh /entrypoint.sh

RUN set -eux; \
  chmod +x /entrypoint.sh; \
  mkdir -p /etc/freeradius/3.0/certs; \
  # Self-signed EAP TLS material for out-of-the-box operation. Replace in production. \
  if [ ! -f /etc/freeradius/3.0/certs/server.key ]; then \
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/freeradius/3.0/certs/server.key \
      -out /etc/freeradius/3.0/certs/server.pem \
      -days 3650 -sha256 \
      -subj "/CN=centralwifi-radius"; \
  fi; \
  if [ ! -f /etc/freeradius/3.0/certs/ca.pem ]; then \
    cp /etc/freeradius/3.0/certs/server.pem /etc/freeradius/3.0/certs/ca.pem; \
  fi; \
  chown -R freerad:freerad /etc/freeradius/3.0

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
