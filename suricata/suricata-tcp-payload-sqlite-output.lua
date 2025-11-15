-- Copyright (C) 2024  ANSSI
-- Copyright (C) 2025  A. Iooss
-- SPDX-License-Identifier: GPL-2.0-or-later

-- This Suricata plugin logs TCP flows data to a SQLite database.

local config = require("suricata.config")
local flow = require("suricata.flow")
local logger = require("suricata.log")

function init (args)
    return {streaming = "tcp"}
end

function setup (args)
    logger.notice("Initializing plugin TCP payload SQLite Output")

    -- open database in WAL mode and init schema
    sqlite3 = require("lsqlite3")
    database = sqlite3.open(config.log_path() .. "/payload.db")
    assert(database:exec([[
        PRAGMA journal_mode=wal;
        PRAGMA synchronous=off;
        CREATE TABLE IF NOT EXISTS raw (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            count INTEGER,
            server_to_client INTEGER,
            sz INT,
            data BLOB,
            UNIQUE(flow_id, count)
        );
        CREATE INDEX IF NOT EXISTS "raw_flow_id_idx" ON raw(flow_id);
    ]]) == sqlite3.OK)
    stmt = database:prepare("INSERT OR IGNORE INTO raw (flow_id, count, server_to_client, sz, data) values(?, ?, ?, ?, ?);")

    -- packer counter for each flow
    flow_pkt_count = {}
    flow_pkt_count_total = 0
end

function log (args)
    local data = args["stream"]["data"]
    local toclient = args["stream"]["to_client"]
    local f = flow.get()

    -- create log entry
    local flow_id = f:id()
    if flow_pkt_count[flow_id] == nil then
        flow_pkt_count[flow_id] = 0
    else
        flow_pkt_count[flow_id] = flow_pkt_count[flow_id] + 1
    end
    local count = flow_pkt_count[flow_id]
    flow_pkt_count_total = flow_pkt_count_total + 1

    if #data == 0 then
        return
    end
    local direction = "0"
    if toclient then
        direction = "1"
    end
    assert(stmt:reset() == sqlite3.OK)
    assert(stmt:bind_values(flow_id, count, direction, #data, data) == sqlite3.OK)
    assert(stmt:step() == sqlite3.DONE)
end

function deinit (args)
    logger.notice("TCP payloads logged: " .. flow_pkt_count_total)
    database:close()
end
