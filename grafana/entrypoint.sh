#!/bin/bash
# Copyright (C) 2025  A. Iooss
# SPDX-License-Identifier: GPL-2.0-or-later

# Convert CTF_SERVICES format to "key : value, key : value"
tmp=""
for name in $(echo "${CTF_SERVICES}" | tr ',' '\n'); do
    varname=$(echo "CTF_SERVICE_$name" | tr '[:lower:]' '[:upper:]')
    for ipaddr in $(echo "${!varname}" | tr ',' '\n'); do
        tmp="$tmp, $name ($ipaddr) : $ipaddr"
    done
done
CTF_SERVICES="${tmp:2}"

# Provision dashboards and substitute variables
mkdir -p /var/lib/grafana/dashboards
for file in /dashboards_template/*.json; do
    echo "Provisionning dashboard $file with environment variables"
    sed -e "s|\$CTF_START_DATE|$CTF_START_DATE|g" \
        -e "s|\$CTF_TICK_LENGTH|${CTF_TICK_LENGTH:=60}|g" \
        -e "s|\$CTF_SHOVEL_URL|${CTF_SHOVEL_URL:=http://localhost:8000}|g" \
        -e "s|\$CTF_SERVICES|$CTF_SERVICES|g" "$file" \
        >"/var/lib/grafana/dashboards/$(basename "$file")"
done

# Run Grafana image entrypoint
/run.sh
