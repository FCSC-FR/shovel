# Copyright (C) 2026  A. Iooss
# SPDX-License-Identifier: CC0-1.0
FROM rust:1.97 AS builder
WORKDIR /src/
COPY Cargo.lock Cargo.toml /src/
COPY suricata-eve-sql-output/ /src/suricata-eve-sql-output/
COPY suricata-filedata-sql-output/ /src/suricata-filedata-sql-output/
COPY suricata-rawdata-sql-output/ /src/suricata-rawdata-sql-output/
COPY suricata-shovel-fuzzyhash/ /src/suricata-shovel-fuzzyhash/
RUN cargo build --release

FROM jasonish/suricata:8.0.6
RUN dnf install -y netcat && dnf clean all
COPY . /suricata
COPY --from=builder /src/target/release/*.so /suricata/
ENTRYPOINT ["/suricata/entrypoint.sh"]
