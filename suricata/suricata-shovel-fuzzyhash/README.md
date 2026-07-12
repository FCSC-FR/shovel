
<!--
Copyright (C) 2026  A. Iooss
SPDX-License-Identifier: CC0-1.0
-->

This plugin spawns a thread to compute flows fuzzyhash in a PostgreSQL database.
It reads `flow` table and writes `flow-fuzzyhash` table.
It could have been a separate executable, but managing this worker with Suricata simplifies the architecture.

The chosen fuzzyhash algorithm is ssdeep.
