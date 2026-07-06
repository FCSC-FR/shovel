-- Copyright (C) 2026  A. Iooss
-- SPDX-License-Identifier: GPL-2.0-or-later

-- This files contain additionnal tables required by Shovel.
-- It only applies when running the plugin using PostgreSQL.

-- Shovel filtering performance
CREATE INDEX IF NOT EXISTS "flow_ts_start_idx" ON flow(ts_start);
CREATE INDEX IF NOT EXISTS "flow_app_proto_idx" ON flow(app_proto);
CREATE INDEX IF NOT EXISTS "flow_src_port_idx" ON flow(src_port);
CREATE INDEX IF NOT EXISTS "flow_dest_port_idx" ON flow(dest_port);
CREATE INDEX IF NOT EXISTS "other-event_flow_id_idx" ON "other-event"(flow_id);

-- Grafana Suricata dashboard performance
CREATE INDEX IF NOT EXISTS "other-event_stats" ON "other-event"(timestamp) WHERE event_type='stats';
CREATE OR REPLACE VIEW "stats" AS SELECT timestamp, extra_data FROM "other-event" WHERE event_type = 'stats';

-- Search alerts by flow or by tag, and return tag/color for flowlist
CREATE INDEX IF NOT EXISTS "other-event_alert_tag" ON "other-event"((extra_data#>>'{metadata,tag,0}')) WHERE event_type='alert';
CREATE INDEX IF NOT EXISTS "other-event_alert_flow_id" ON "other-event"(flow_id) WHERE event_type='alert';
CREATE OR REPLACE VIEW "alert" AS
    SELECT flow_id, extra_data#>>'{metadata,tag,0}' AS tag, extra_data#>>'{metadata,color,0}' AS color
    FROM "other-event" WHERE event_type = 'alert';

-- Distinct app protocols list
-- Equivalent of `SELECT DISTINCT app_proto FROM flow`, but optimized
-- see https://wiki.postgresql.org/wiki/Loose_indexscan
CREATE OR REPLACE VIEW "app_protos" AS WITH RECURSIVE t AS (
    (SELECT app_proto FROM flow ORDER BY app_proto LIMIT 1) UNION ALL SELECT
        (SELECT app_proto FROM flow WHERE app_proto > t.app_proto ORDER BY app_proto LIMIT 1)
    FROM t WHERE t.app_proto IS NOT NULL
) SELECT app_proto FROM t WHERE app_proto IS NOT NULL;

-- Distinct tags list
-- Equivalent of `SELECT DISTINCT tag FROM alert`, but optimized
-- see https://wiki.postgresql.org/wiki/Loose_indexscan
CREATE OR REPLACE VIEW "tags" AS WITH RECURSIVE t AS (
    (SELECT tag, color FROM alert ORDER BY tag LIMIT 1) UNION ALL SELECT
        (SELECT tag FROM alert WHERE tag > t.tag ORDER BY tag LIMIT 1),
        (SELECT color FROM alert WHERE tag > t.tag ORDER BY tag LIMIT 1)
    FROM t WHERE t.tag IS NOT NULL
) SELECT tag, color FROM t WHERE tag IS NOT NULL;
