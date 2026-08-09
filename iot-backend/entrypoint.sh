#!/bin/sh
mkdir -p /app/data
chown -R appuser:appuser /app/data
exec su appuser -c "$*"
