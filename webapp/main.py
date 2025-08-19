#!/usr/bin/env python3
# Copyright (C) 2023-2024  ANSSI
# Copyright (C) 2025  A. Iooss
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import contextlib
import glob
import json
import time
from pathlib import Path

import aiosqlite
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates


def row_to_dict(row: aiosqlite.Row) -> dict:
    row_dict = dict(row)
    metadata = json.loads(row_dict.pop("metadata", "{}") or "{}")
    row_dict.update(metadata)
    extra_data = json.loads(row_dict.pop("extra_data", "{}") or "{}")
    row_dict.update(extra_data)
    return row_dict


async def index(request):
    context = {
        "request": request,
        "ctf_config": CTF_CONFIG,
    }
    return templates.TemplateResponse("index.html.jinja2", context)


async def api_filedata_get(request):
    sha256 = request.path_params["sha256"]

    cursor = await filedata_database.execute(
        "SELECT blob FROM filedata WHERE sha256 = ?",
        [bytes.fromhex(sha256)],
    )
    row = await cursor.fetchone()
    return Response(row["blob"], headers={"Cache-Control": "max-age=86400"})


async def api_flow_list(request):
    # Parse GET arguments
    ts_to = request.query_params.get("to", str(int(1e16)))
    services = request.query_params.getlist("service")
    app_proto = request.query_params.get("app_proto")
    search = request.query_params.get("search")
    tags_require = request.query_params.getlist("tag_require")
    tags_deny = request.query_params.getlist("tag_deny")
    if not ts_to.isnumeric():
        raise HTTPException(400)

    # Query flows and associated tags using filters
    query = """
        WITH fsrvs AS (SELECT value FROM json_each(?1)),
          ftags_req AS (SELECT value FROM json_each(?2)),
          ftags_deny AS (SELECT value FROM json_each(?3)),
          fsearchfid AS (SELECT value FROM json_each(?6))
        SELECT id, ts_start, ts_end, dest_ipport, app_proto, metadata,
          (SELECT GROUP_CONCAT(tag) FROM alert WHERE flow_id = flow.id) AS tags
        FROM flow WHERE ts_start <= ?4 AND (?5 = app_proto OR ?5 IS NULL)
    """
    if services == ["!"]:
        # Filter flows related to no services
        query += "AND NOT (src_ipport IN fsrvs OR dest_ipport IN fsrvs)"
        services = sum(CTF_CONFIG["services"].values(), [])
    elif services:
        query += "AND (src_ipport IN fsrvs OR dest_ipport IN fsrvs)"
    if tags_deny:
        # No alert with at least a denied tag exists for this flow
        query += """
            AND NOT EXISTS (
                SELECT 1 FROM alert
                WHERE flow_id == flow.id AND alert.tag IN ftags_deny
            )
        """
    if tags_require:
        # Relational division to get all flow_id matching all chosen tags
        query += """
            AND flow.id IN (
                SELECT flow_id FROM alert WHERE tag IN ftags_req GROUP BY flow_id
                HAVING COUNT(*) = (SELECT COUNT(*) FROM ftags_req)
            )
        """
    search_fid = []
    if search:
        # Collect all flows id with raw payload matching search
        cursor = await payload_database.execute(
            "SELECT flow_id FROM raw WHERE blob GLOB ?1",
            (f"*{search}*",),
        )
        rows = await cursor.fetchall()
        search_fid = [r["flow_id"] for r in rows]

        # Collect all flows id with filedata matching search
        cursor = await filedata_database.execute(
            "SELECT sha256 FROM filedata WHERE blob GLOB ?1",
            (f"*{search}*",),
        )
        rows = await cursor.fetchall()
        filedata_sha256 = [r["sha256"].hex() for r in rows]
        cursor = await eve_database.execute(
            "WITH fsha256 AS (SELECT value FROM json_each(?1)) "
            "SELECT flow_id FROM 'other-event' "
            "WHERE event_type = 'fileinfo' AND extra_data->>'sha256' IN fsha256",
            (json.dumps(filedata_sha256),),
        )
        rows = await cursor.fetchall()
        search_fid += [r["flow_id"] for r in rows]

        query += " AND flow.id IN fsearchfid"
    query += " ORDER BY ts_start DESC LIMIT 100"

    cursor = await eve_database.execute(
        query,
        (
            json.dumps(services),
            json.dumps(tags_require),
            json.dumps(tags_deny),
            int(ts_to),
            "failed" if app_proto == "raw" else app_proto,
            json.dumps(search_fid),
        ),
    )
    rows = await cursor.fetchall()
    flows = [row_to_dict(row) for row in rows]

    # Fetch application protocols
    cursor = await eve_database.execute("SELECT DISTINCT app_proto FROM flow")
    rows = await cursor.fetchall()
    prs = [r["app_proto"] for r in rows if r["app_proto"] not in [None, "failed"]]

    # Fetch tags
    cursor = await eve_database.execute(
        "SELECT tag, color FROM alert GROUP BY tag ORDER BY color"
    )
    rows = await cursor.fetchall()
    tags = [dict(row) for row in rows]

    return JSONResponse(
        {
            "flows": flows,
            "appProto": prs,
            "tags": tags,
        }
    )


async def api_flow_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow from database
    cursor = await eve_database.execute(
        (
            "SELECT id, ts_start, ts_end, src_ipport, dest_ipport, dest_port, "
            "proto, app_proto, metadata, extra_data FROM flow WHERE id = ?"
        ),
        [flow_id],
    )
    flow = await cursor.fetchone()
    if not flow:
        raise HTTPException(404)
    result = {"flow": row_to_dict(flow)}

    # Get associated events
    cursor = await eve_database.execute(
        "SELECT event_type, extra_data FROM 'other-event' WHERE flow_id = ? ORDER BY id",
        [flow_id],
    )
    for row in await cursor.fetchall():
        result[row["event_type"]] = result.get(row["event_type"], []) + [
            json.loads(row["extra_data"])
        ]

    # Get associated alert
    if result["flow"]["alerted"]:
        cursor = await eve_database.execute(
            "SELECT extra_data, color FROM alert WHERE flow_id = ? ORDER BY id",
            [flow_id],
        )
        rows = await cursor.fetchall()
        result["alert"] = [row_to_dict(f) for f in rows]

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_flow_pcap_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow start timestamp from database
    cursor = await eve_database.execute(
        "SELECT ts_start FROM flow WHERE id = ?", [flow_id]
    )
    flow = await cursor.fetchone()
    if not flow:
        raise HTTPException(404)
    flow_us = flow["ts_start"] // 1000

    # Serve corresponding pcap, found using timestamp
    flow_pcap_path = ""
    for pcap_path in sorted(glob.glob("../suricata/output/pcaps/*.*")):
        pcap_us = int(pcap_path.replace(".lz4", "").rsplit(".", 1)[-1])
        if pcap_us > flow_us:
            break  # take previous one
        flow_pcap_path = pcap_path
    if not flow_pcap_path:
        raise HTTPException(404)
    filename = f"{flow_id}_" + Path(flow_pcap_path).name
    return FileResponse(
        flow_pcap_path, content_disposition_type="attachment", filename=filename
    )


async def api_flow_raw_get(request):
    flow_id = request.path_params["flow_id"]

    # Get associated raw data
    cursor = await payload_database.execute(
        "SELECT server_to_client, blob FROM raw WHERE flow_id = ?1 ORDER BY count",
        [flow_id],
    )
    rows = await cursor.fetchall()
    result = []
    for r in rows:
        data = base64.b64encode(r["blob"]).decode()
        result.append({"server_to_client": r["server_to_client"], "data": data})

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_replay_http(request):
    flow_id = request.path_params["flow_id"]

    # Get HTTP events
    cursor = await eve_database.execute(
        "SELECT flow_id, extra_data FROM 'other-event' WHERE flow_id = ? AND event_type = 'http' ORDER BY id",
        [flow_id],
    )
    rows = await cursor.fetchall()

    # For each HTTP request, load client payload if it exists
    data = []
    for tx_id, row in enumerate(rows):
        req = row_to_dict(row)
        req["rq_content"] = None
        if req["http_method"] in ["POST"]:
            # First result should be the request
            cursor = await eve_database.execute(
                "SELECT extra_data FROM 'other-event' WHERE flow_id = ? AND event_type = 'fileinfo' AND extra_data->>'tx_id' = ? ORDER BY id",
                [flow_id, tx_id],
            )
            fileinfo_first_event = await cursor.fetchone()
            if not fileinfo_first_event:
                raise HTTPException(404)
            sha256 = json.loads(fileinfo_first_event["extra_data"]).get("sha256")
            if not sha256:
                raise HTTPException(500)

            # Load filedata
            cursor = await filedata_database.execute(
                "SELECT blob FROM filedata WHERE sha256 = ?",
                (bytes.fromhex(sha256),),
            )
            row = await cursor.fetchone()
            req["rq_content"] = row["blob"]
        data.append(req)

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "http-replay.py.jinja2", context, media_type="text/plain"
    )


async def api_replay_raw(request):
    flow_id = request.path_params["flow_id"]

    # Get flow event
    cursor = await eve_database.execute(
        "SELECT dest_ipport, proto FROM flow WHERE id = ?",
        [flow_id],
    )
    flow_event = await cursor.fetchone()
    if not flow_event:
        raise HTTPException(404)
    ip, port = flow_event["dest_ipport"].rsplit(":", 1)
    data = {
        "flow_id": flow_id,
        "ip": ip,
        "port": port,
        "dest_ipport": flow_event["dest_ipport"],
        "proto": flow_event["proto"],
    }

    # Get associated raw data
    cursor = await payload_database.execute(
        "SELECT server_to_client, blob FROM raw WHERE flow_id = ?1 ORDER BY count",
        [flow_id],
    )
    rows = await cursor.fetchall()
    if not rows:
        raise HTTPException(404)

    # Load files
    data["raw_data"] = []
    for row in rows:
        sc, raw_data = row["server_to_client"], row["blob"]
        if data["raw_data"] and data["raw_data"][-1][1] == sc and sc == 1:
            # Concat servers messages together
            data["raw_data"][-1][0] += raw_data
        else:
            data["raw_data"].append([raw_data, sc])

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "raw-replay.py.jinja2", context, media_type="text/plain"
    )


async def open_database(database_uri: str, text_factory=str) -> aiosqlite.Connection:
    while True:
        try:
            con = await aiosqlite.connect(database_uri, uri=True)
        except aiosqlite.OperationalError as e:
            print(f"Unable to open database '{database_uri}': {e}", flush=True)
            time.sleep(1)
            continue
        break
    con.row_factory = aiosqlite.Row
    con.text_factory = text_factory
    return con


@contextlib.asynccontextmanager
async def lifespan(app):
    """
    Open databases on startup.
    Close databases on exit.
    """
    global eve_database, payload_database, filedata_database
    eve_database = await open_database(EVE_DB_URI)
    payload_database = await open_database(PAYLOAD_DB_URI, bytes)
    filedata_database = await open_database(FILEDATA_DB_URI, bytes)
    yield
    await eve_database.close()
    await payload_database.close()
    await filedata_database.close()


# Load configuration from environment variables, then .env file
config = Config("../.env")
DEBUG = config("DEBUG", cast=bool, default=False)
EVE_DB_URI = config(
    "EVE_DB_URI", cast=str, default="file:../suricata/output/eve.db?mode=ro"
)
PAYLOAD_DB_URI = config(
    "PAYLOAD_DB_URI", cast=str, default="file:../suricata/output/payload.db?mode=ro"
)
FILEDATA_DB_URI = config(
    "FILEDATA_DB_URI", cast=str, default="file:../suricata/output/filedata.db?mode=ro"
)
CTF_CONFIG = {
    "start_date": config("CTF_START_DATE", cast=str, default="1970-01-01T00:00+00:00"),
    "tick_length": config("CTF_TICK_LENGTH", cast=int, default=0),
    "services": {},
}
service_names = config("CTF_SERVICES", cast=CommaSeparatedStrings, default=[])
for name in service_names:
    ipports = config(f"CTF_SERVICE_{name.upper()}", cast=CommaSeparatedStrings)
    CTF_CONFIG["services"][name] = list(ipports)

# Define web application
eve_database = None
payload_database = None
filedata_database = None
templates = Jinja2Templates(directory="templates")
app = Starlette(
    debug=DEBUG,
    routes=[
        Route("/", index),
        Route("/api/filedata/{sha256:str}", api_filedata_get),
        Route("/api/flow", api_flow_list),
        Route("/api/flow/{flow_id:int}", api_flow_get),
        Route("/api/flow/{flow_id:int}/pcap", api_flow_pcap_get),
        Route("/api/flow/{flow_id:int}/raw", api_flow_raw_get),
        Route("/api/replay-http/{flow_id:int}", api_replay_http),
        Route("/api/replay-raw/{flow_id:int}", api_replay_raw),
        Mount("/static", StaticFiles(directory="static")),
    ],
    lifespan=lifespan,
)
