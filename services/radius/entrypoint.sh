#!/usr/bin/env sh
set -eu

secret="${RADIUS_DEFAULT_SECRET:-testing123}"
sed "s|__RADIUS_DEFAULT_SECRET__|${secret}|g" \
  /etc/freeradius/3.0/clients.conf.template > /etc/freeradius/3.0/clients.conf
chown freerad:freerad /etc/freeradius/3.0/clients.conf

exec freeradius -f
