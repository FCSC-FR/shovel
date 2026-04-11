# Copyright (C) 2023-2024  ANSSI
# SPDX-License-Identifier: CC0-1.0
FROM rust:1.88.0-alpine3.22 AS builder
WORKDIR /src/
RUN apk add --no-cache musl-dev
COPY Cargo.lock Cargo.toml /src/
COPY suricata-eve-sqlite-output/ /src/suricata-eve-sqlite-output/
COPY suricata-filedata-sqlite-output/ /src/suricata-filedata-sqlite-output/
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

# Build pcap-over-ip plugin
# HACK: this plugin should be moved to a standalone plugin in shovel repository
FROM alpine:3.23 AS builder-pcapoverip
RUN apk add --no-cache git libtool cbindgen make autoconf automake cargo file-dev geoip-dev hiredis-dev jansson-dev libbpf-dev libcap-ng-dev libmaxminddb-dev libnetfilter_log-dev libnetfilter_queue-dev libnet-dev libnfnetlink-dev libpcap-dev lz4-dev nspr-dev nss-dev pcre2-dev rust yaml-dev && \
    git clone https://github.com/erdnaxe/suricata -b pcap-over-ip-suricata-8.0.0 --depth 1 && \
    cd suricata && \
    ./autogen.sh && ./configure --enable-pcap-over-ip && \
    cd plugins/pcap-over-ip/ && \
    make

FROM alpine:3.23
RUN apk add --no-cache lua5.4-sqlite netcat-openbsd
# Alpine 3.23 is still on Suricata 8.0.0. Pull 8.0.3 from edge.
RUN apk add --no-cache suricata --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community
COPY . /suricata
COPY --from=builder /src/target/release/*.so /suricata/
COPY --from=builder-pcapoverip /suricata/plugins/pcap-over-ip/.libs/pcap-over-ip.so /suricata/
ENTRYPOINT ["/suricata/entrypoint.sh"]
