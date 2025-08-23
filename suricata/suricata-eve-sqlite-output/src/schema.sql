-- Copyright (C) 2024  ANSSI
-- SPDX-License-Identifier: GPL-2.0-or-later
CREATE TABLE IF NOT EXISTS "flow" (
    id INTEGER NOT NULL PRIMARY KEY,
    ts_start INTEGER,
    ts_end INTEGER,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    proto TEXT NOT NULL,
    app_proto TEXT,
    metadata BLOB,
    extra_data BLOB
);
CREATE TABLE IF NOT EXISTS "alert" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER,
    tag TEXT,
    color TEXT,
    timestamp INTEGER NOT NULL,
    extra_data BLOB,
    UNIQUE(flow_id, tag)
);
CREATE TABLE IF NOT EXISTS "other-event" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    extra_data BLOB,
    UNIQUE(flow_id, event_type, timestamp)
);
CREATE INDEX IF NOT EXISTS "flow_ts_start_idx" ON flow(ts_start);
CREATE INDEX IF NOT EXISTS "flow_app_proto_idx" ON flow(app_proto);
CREATE INDEX IF NOT EXISTS "flow_src_port_idx" ON flow(src_port);
CREATE INDEX IF NOT EXISTS "flow_dest_port_idx" ON flow(dest_port);
CREATE INDEX IF NOT EXISTS "alert_tag_idx" ON alert(tag);
CREATE INDEX IF NOT EXISTS "alert_flow_id_idx" ON alert(flow_id);
CREATE INDEX IF NOT EXISTS "other-event_flow_id_idx" ON "other-event"(flow_id);
