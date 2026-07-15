
<!--
Copyright (C) 2026  A. Iooss
SPDX-License-Identifier: CC0-1.0
-->

This plugin spawns a thread to compute flows fuzzyhash in a PostgreSQL database.
It reads `other-event`, `filedata` and `rawdata` tables and writes `flow-fuzzyhash` table.
It could have been a separate executable, but managing this worker with Suricata simplifies the architecture.

## Hashing choices

The chosen fuzzyhash algorithm is ssdeep.

Rather than hashing all Eve events associated with each flow, only filedata (or rawdata if none) are hashed.
Then, the frontend is responsible for computing the distance between fuzzyhashes
and pondering the sum with other factors such as the difference of duration between the flows.
