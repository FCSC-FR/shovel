-- Copyright (C) 2026  A. Iooss
-- SPDX-License-Identifier: GPL-2.0-or-later

-- These tables are kept close to Eve structure
CREATE TABLE IF NOT EXISTS "flow" (
    id BIGINT NOT NULL PRIMARY KEY,
    ts_start BIGINT,
    ts_end BIGINT,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    proto TEXT NOT NULL,
    app_proto TEXT,
    metadata JSONB,
    extra_data JSONB
);
-- anomaly and stats events don't have a flow_id, so don't mark as NOT NULL
CREATE TABLE IF NOT EXISTS "other-event" (
    flow_id BIGINT,
    timestamp BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    extra_data JSONB,
    UNIQUE(flow_id, event_type, timestamp)
);
