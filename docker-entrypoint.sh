#!/bin/sh
set -eu

mkdir -p /data
if [ "$(id -u)" = "0" ]; then
  # Older volumes may be root-owned. Repair ownership once; running recursive
  # chown on every boot becomes very slow as user uploads and logs accumulate.
  marker=/data/.mazagi_permissions_v1
  if [ ! -f "$marker" ]; then
    chown -R mazagi:mazagi /data
    touch "$marker"
    chown mazagi:mazagi "$marker"
    chmod 600 "$marker"
  else
    chown mazagi:mazagi /data
  fi
  exec gosu mazagi "$@"
fi
exec "$@"
