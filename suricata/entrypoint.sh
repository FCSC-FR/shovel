#!/bin/sh
# Copyright (C) 2024  ANSSI
# SPDX-License-Identifier: CC0-1.0

# pipefail: exit Suricata if pcap-over-ip connection ends
set -euo pipefail

SURICATA_CMD="suricata"
if [ -n "${PCAP_OVER_IP+x}" ]; then
    PCAP_OVER_IP=$(echo "$PCAP_OVER_IP" | tr ":" " ")
    SURICATA_CMD="nc -d $PCAP_OVER_IP | $SURICATA_CMD"
fi

# Arguments override default Suricata configuration,
# see https://github.com/OISF/suricata/blob/suricata-8.0.0/suricata.yaml.in
# and `suricata --dump-config`
mkdir -p suricata/output/pcaps
eval "$SURICATA_CMD" \
    --runmode=single --no-random -k none \
    -l suricata/output \
    --set default-rule-path=suricata/rules \
    --set plugins.0=suricata/libeve_sqlite_output.so \
    --set plugins.1=suricata/libfiledata_sqlite_output.so \
    --set outputs.0.fast.enabled=no \
    --set outputs.1.eve-log.filetype=sqlite \
    --set outputs.1.eve-log.types.2.anomaly.types.decode=yes \
    --set outputs.1.eve-log.types.2.anomaly.types.stream=yes \
    --set outputs.1.eve-log.types.2.anomaly.types.applayer=yes \
    --set outputs.1.eve-log.types.3.http.dump-all-headers=both \
    --set outputs.1.eve-log.types.7.files.force-hash.0=sha256 \
    --set outputs.1.eve-log.types.28.mqtt.passwords=yes \
    --set outputs.1.eve-log.types.31.pgsql.enabled=yes \
    --set outputs.1.eve-log.types.31.pgsql.passwords=yes \
    --set outputs.3.pcap-log.enabled="${PCAP_LOG:=yes}" \
    --set outputs.3.pcap-log.limit=33554432 \
    --set outputs.3.pcap-log.compression=lz4 \
    --set outputs.3.pcap-log.dir=pcaps \
    --set outputs.5.stats.enabled=no \
    --set outputs.9.lua.enabled=yes \
    --set outputs.9.lua.cpath=/usr/lib/lua/5.4/?.so \
    --set outputs.9.lua.scripts.0=suricata/suricata-tcp-payload-sqlite-output.lua \
    --set outputs.9.lua.scripts.1=suricata/suricata-udp-payload-sqlite-output.lua \
    --set app-layer.protocols.pgsql.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.enip.enabled=yes \
    --set app-layer.protocols.http.libhtp.default-config.request-body-limit=52428800 \
    --set app-layer.protocols.http.libhtp.default-config.response-body-limit=0 \
    --set app-layer.protocols.sip.enabled=no \
    --set stream.reassembly.depth=50mb \
    --set flow-timeouts.tcp.established=60 \
    --set flow-timeouts.tcp.emergency-established=60 \
    --set flow-timeouts.tcp.closed=5 \
    --set flow-timeouts.tcp.emergency-closed=5 \
    --set flow-timeouts.udp.new=10 \
    --set flow-timeouts.udp.established=10 \
    --set flow-timeouts.udp.emergency-established=10 \
    --set security.lua.allow-rules=yes \
    "$*"
