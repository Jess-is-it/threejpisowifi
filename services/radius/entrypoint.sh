#!/usr/bin/env sh
set -eu

secret="${RADIUS_DEFAULT_SECRET:-testing123}"
sed "s|__RADIUS_DEFAULT_SECRET__|${secret}|g" \
  /etc/freeradius/3.0/clients.conf.template > /etc/freeradius/3.0/clients.conf
chown freerad:freerad /etc/freeradius/3.0/clients.conf

cat > /opt/radius/runtime.env <<EOF
DATABASE_URL=${DATABASE_URL:-}
ACTIVE_SESSION_GRACE_SECONDS=${ACTIVE_SESSION_GRACE_SECONDS:-180}
EOF
chown freerad:freerad /opt/radius/runtime.env
chmod 600 /opt/radius/runtime.env

exec freeradius -f
