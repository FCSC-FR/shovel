-- Copyright (C) 2024  ANSSI
-- Copyright (C) 2025  A. Iooss
-- SPDX-License-Identifier: GPL-2.0-or-later

-- This Suricata plugin logs UDP frames data to a SQLite database.

local config = require("suricata.config")
local flow = require("suricata.flow")
local logger = require("suricata.log")
local packet = require("suricata.packet")

function init (args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup (args)
    logger.notice("Initializing plugin UDP payload SQLite Output")

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
            blob BLOB,
            UNIQUE(flow_id, count)
        );
        CREATE INDEX IF NOT EXISTS "raw_flow_id_idx" ON raw(flow_id);
    ]]) == sqlite3.OK)
    stmt = database:prepare("INSERT OR IGNORE INTO raw (flow_id, count, server_to_client, blob) values(?, ?, ?, ?);")

    -- packer counter for each flow
    flow_pkt_count = {}
    flow_pkt_count_total = 0
end

function log (args)
    local p = packet.get()
    local f = flow.get()

    -- drop if not UDP (17)
    -- https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    local ipver, srcip, dstip, proto, sp, dp = p:tuple()
    if proto ~= 17 then
        return
    end

    -- get packet direction
    local ipver, srcip_flow, dstip_flow, proto, sp_flow, dp_flow = f:tuple()
    local direction = "1"
    if srcip == srcip_flow and dstip == dstip_flow and sp == sp_flow and dp == dp_flow then
        direction = "0"
    end

    -- create log entry
    local flow_id = f:id()
    if flow_pkt_count[flow_id] == nil then
        flow_pkt_count[flow_id] = 0
    else
        flow_pkt_count[flow_id] = flow_pkt_count[flow_id] + 1
    end
    local count = flow_pkt_count[flow_id]
    flow_pkt_count_total = flow_pkt_count_total + 1
    local data = p:payload()
    if #data == 0 then
        return
    end
    assert(stmt:reset() == sqlite3.OK)
    assert(stmt:bind_values(flow_id, count, direction, data) == sqlite3.OK)
    assert(stmt:step() == sqlite3.DONE)
end

function deinit (args)
    logger.notice("UDP payloads logged: " .. flow_pkt_count_total)
    database:close()
end
