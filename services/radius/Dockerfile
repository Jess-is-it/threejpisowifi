FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends freeradius freeradius-postgresql python3 python3-psycopg python3-passlib python3-bcrypt ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY mods-available/exec /etc/freeradius/3.0/mods-available/exec
COPY sites-enabled/default /etc/freeradius/3.0/sites-enabled/default
COPY clients.conf.template /etc/freeradius/3.0/clients.conf.template
COPY entrypoint.sh /entrypoint.sh
COPY scripts /opt/radius

RUN ln -sf /etc/freeradius/3.0/mods-available/exec /etc/freeradius/3.0/mods-enabled/exec \
    && chmod +x /opt/radius/*.py \
    && chmod +x /entrypoint.sh \
    && chown -R freerad:freerad /etc/freeradius/3.0 /opt/radius

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/entrypoint.sh"]
