#!/usr/bin/env python3
# Copyright (C) 2023-2024  ANSSI
# Copyright (C) 2025  A. Iooss
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import base64
import contextlib
import io
import itertools
import json
import time
from pathlib import Path

import aiosqlite
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from pcap import stream_pcaps_with_bpf


def row_to_dict(row: aiosqlite.Row) -> dict:
    row_dict = dict(row)
    metadata = json.loads(row_dict.pop("json(metadata)", "{}") or "{}")
    row_dict.update(metadata)
    extra_data = json.loads(row_dict.pop("json(extra_data)", "{}") or "{}")
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

    async with filedata_db.execute(
        "SELECT sz, data FROM sqlar WHERE name = ?", (sha256,)
    ) as cursor:
        row = await cursor.fetchone()
        data = row["data"]
    extra_header = {"Content-Encoding": "deflate"} if row["sz"] != len(data) else {}
    return Response(data, headers={"Cache-Control": "max-age=86400"} | extra_header)


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
        SELECT id, ts_start, ts_end, dest_ip, dest_port, app_proto, json(metadata),
          (SELECT GROUP_CONCAT(tag) FROM alert WHERE flow_id = flow.id) AS tags
        FROM flow WHERE ts_start <= ?4 AND (?5 = app_proto OR ?5 IS NULL)
    """
    if services == ["!"]:
        # Filter flows related to no services
        query += "AND NOT ((src_ip||':'||src_port) IN fsrvs OR (dest_ip||':'||dest_port) IN fsrvs)"
        services = sum(CTF_CONFIG["services"].values(), [])
    elif services:
        query += "AND ((src_ip||':'||src_port) IN fsrvs OR (dest_ip||':'||dest_port) IN fsrvs)"
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
        async with payload_db.execute(
            "SELECT flow_id FROM raw WHERE data GLOB ?1", (f"*{search}*",)
        ) as cursor:
            rows = await cursor.fetchall()
            search_fid = [r["flow_id"] for r in rows]

        # Collect all flows id with uncompressed filedata matching search
        async with filedata_db.execute(
            "SELECT name FROM sqlar WHERE length(data) == sz AND data GLOB ?1",
            (f"*{search}*",),
        ) as cursor:
            rows = await cursor.fetchall()
            filedata_sha256 = [r["name"].decode() for r in rows]
        async with eve_db.execute(
            "WITH fsha256 AS (SELECT value FROM json_each(?1)) "
            "SELECT flow_id FROM 'other-event' "
            "WHERE event_type = 'fileinfo' AND extra_data->>'sha256' IN fsha256",
            (json.dumps(filedata_sha256),),
        ) as cursor:
            rows = await cursor.fetchall()
            search_fid += [r["flow_id"] for r in rows]

        query += " AND flow.id IN fsearchfid"
    query += " ORDER BY ts_start DESC LIMIT 100"

    async with eve_db.execute(
        query,
        (
            json.dumps(services),
            json.dumps(tags_require),
            json.dumps(tags_deny),
            int(ts_to),
            "failed" if app_proto == "raw" else app_proto,
            json.dumps(search_fid),
        ),
    ) as cursor:
        rows = await cursor.fetchall()
        flows = [row_to_dict(row) for row in rows]

    return JSONResponse({"flows": flows})


async def api_flow_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow from database
    async with eve_db.execute(
        (
            "SELECT id, ts_start, ts_end, src_ip, src_port, dest_ip, dest_port, "
            "proto, app_proto, json(metadata), json(extra_data) FROM flow WHERE id = ?"
        ),
        (flow_id,),
    ) as cursor:
        flow = await cursor.fetchone()
        if not flow:
            raise HTTPException(404)
        result = {"flow": row_to_dict(flow)}

    # Get associated events
    async with eve_db.execute(
        "SELECT event_type, json(extra_data) FROM 'other-event' WHERE flow_id = ? ORDER BY id",
        (flow_id,),
    ) as cursor:
        for row in await cursor.fetchall():
            result[row["event_type"]] = result.get(row["event_type"], []) + [
                json.loads(row["json(extra_data)"])
            ]

    # Get associated alert
    if result["flow"]["alerted"]:
        async with eve_db.execute(
            "SELECT json(extra_data), color FROM alert WHERE flow_id = ? ORDER BY id",
            (flow_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            result["alert"] = [row_to_dict(f) for f in rows]

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_flow_pcap_get(request):
    flow_id = request.path_params["flow_id"]

    # Query flow start timestamp from database
    async with eve_db.execute(
        "SELECT ts_start, ts_end, src_ip, src_port, dest_ip, dest_port FROM flow WHERE id = ?",
        (flow_id,),
    ) as cursor:
        flow = await cursor.fetchone()
        if not flow:
            raise HTTPException(404)

    # convert μs to seconds
    flow_start_secs = flow["ts_start"] // 1000_000
    flow_end_secs = flow["ts_end"] // 1000_000

    # Build the BPF filter for this flow
    src_ip = flow["src_ip"].strip("[]")
    src_port = flow["src_port"]
    dst_ip = flow["dest_ip"].strip("[]")
    dst_port = flow["dest_port"]
    bpf_filter = (
        f"host {src_ip} and host {dst_ip} and " f"port {src_port} and port {dst_port}"
    )

    # Serve corresponding pcap, found using timestamp
    pcaps = []
    pcap_paths = list(sorted(Path("../suricata/output/pcaps/").glob("*.*")))
    timestamps = [
        int(str(pcap_path).replace(".lz4", "").rsplit(".", 1)[-1])
        for pcap_path in pcap_paths
    ]

    # create pairs of (start, end) timestamps for each pcap
    start_end_stamps = list(itertools.zip_longest(timestamps, timestamps[1:]))

    # Find pcaps overlapping with the flow's time range
    for pcap_path, pcap_start_end in zip(pcap_paths, start_end_stamps):
        pcap_start, pcap_end = pcap_start_end
        # Check if flow overlaps with this PCAP's time range
        # For the last PCAP (pcap_end is None), only check if flow ends after pcap starts
        if pcap_end is None:
            # Last PCAP: include if flow hasn't ended before this PCAP started
            if flow_end_secs > pcap_start:
                pcaps.append(pcap_path)
        else:
            # Normal overlap check for PCAPs with known end time
            if flow_start_secs < pcap_end and flow_end_secs > pcap_start:
                pcaps.append(pcap_path)

    if not pcaps:
        raise HTTPException(404)

    filename = f"flow-{flow_id}.pcap"
    return StreamingResponse(
        stream_pcaps_with_bpf(pcaps, bpf_filter),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def api_flow_raw_get(request):
    flow_id = request.path_params["flow_id"]

    # Get associated raw data
    async with payload_db.execute(
        "SELECT server_to_client, data FROM raw WHERE flow_id = ?1 ORDER BY count",
        (flow_id,),
    ) as cursor:
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            data = base64.b64encode(r["data"]).decode()
            result.append({"server_to_client": r["server_to_client"], "data": data})

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_replay_http(request):
    flow_id = request.path_params["flow_id"]

    # Get HTTP events
    async with eve_db.execute(
        "SELECT flow_id, json(extra_data) FROM 'other-event' WHERE flow_id = ? AND event_type = 'http' ORDER BY id",
        (flow_id,),
    ) as cursor:
        rows = await cursor.fetchall()

    # For each HTTP request, load client payload if it exists
    data = []
    for tx_id, row in enumerate(rows):
        req = row_to_dict(row)
        req["rq_content"] = None
        if req["http_method"] in ["POST"]:
            # First result should be the request
            async with eve_db.execute(
                "SELECT extra_data->>'sha256' AS sha256 FROM 'other-event' WHERE flow_id = ? AND event_type = 'fileinfo' AND extra_data->>'tx_id' = ? ORDER BY id",
                (flow_id, tx_id),
            ) as cursor:
                fileinfo_first_event = await cursor.fetchone()
                if not fileinfo_first_event:
                    raise HTTPException(404)
                sha256 = fileinfo_first_event["sha256"]

            # Load filedata
            async with filedata_db.execute(
                "SELECT sz, data FROM sqlar WHERE name = ?",
                (sha256,),
            ) as cursor:
                row = await cursor.fetchone()
                d, sz = row["data"], row["sz"]
                req["rq_content"] = f"[TODO] {sz} bytes".encode() if sz != len(d) else d
        data.append(req)

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "http-replay.py.jinja2", context, media_type="text/plain"
    )


async def api_replay_raw(request):
    flow_id = request.path_params["flow_id"]

    # Get flow event
    async with eve_db.execute(
        "SELECT dest_ip, dest_port, proto FROM flow WHERE id = ?", (flow_id,)
    ) as cursor:
        flow_event = await cursor.fetchone()
        if not flow_event:
            raise HTTPException(404)
        data = {
            "flow_id": flow_id,
            "ip": flow_event["dest_ip"],
            "port": flow_event["dest_port"],
            "proto": flow_event["proto"],
        }

    # Get associated raw data
    async with payload_db.execute(
        "SELECT server_to_client, data FROM raw WHERE flow_id = ?1 ORDER BY count",
        (flow_id,),
    ) as cursor:
        rows = await cursor.fetchall()
        if not rows:
            raise HTTPException(404)

    # Load files
    data["raw_data"] = []
    for row in rows:
        sc, raw_data = row["server_to_client"], row["data"]
        if data["raw_data"] and data["raw_data"][-1][1] == sc and sc == 1:
            # Concat servers messages together
            data["raw_data"][-1][0] += raw_data
        else:
            data["raw_data"].append([raw_data, sc])

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "raw-replay.py.jinja2", context, media_type="text/plain"
    )


async def stream_events():
    last_ts_minmax, last_prs, last_tags = (-1, -1), None, None
    config_sent = False
    try:
        while True:
            # Get first and last flow timestamp, application protocols and tags
            async with eve_db.execute(
                "SELECT MIN(ts_start) as min, MAX(ts_start) as max FROM flow", ()
            ) as cursor:
                row = await cursor.fetchone()
                ts_minmax = row["min"], row["max"]
            async with eve_db.execute("SELECT DISTINCT app_proto FROM flow") as cursor:
                rows = await cursor.fetchall()
                prs = [
                    r["app_proto"]
                    for r in rows
                    if r["app_proto"] not in [None, "failed"]
                ]
            async with eve_db.execute(
                "SELECT tag, color FROM alert GROUP BY tag ORDER BY color"
            ) as cursor:
                rows = await cursor.fetchall()
                tags = [dict(row) for row in rows]

            # Send delta to client
            if ts_minmax != last_ts_minmax:
                yield f"event: timestampMinMax\ndata: {json.dumps(ts_minmax)}\n\n"
            if prs != last_prs:
                yield f"event: appProto\ndata: {json.dumps(prs)}\n\n"
            if tags != last_tags:
                yield f"event: tags\ndata: {json.dumps(tags)}\n\n"
            if not config_sent:  # Must be last event, trigger flows query
                yield f"event: config\ndata: {json.dumps(CTF_CONFIG)}\n\n"
            last_ts_minmax, last_prs, last_tags = ts_minmax, prs, tags
            config_sent = True
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        yield "event: close\n\n"


async def api_events(request):
    return StreamingResponse(
        stream_events(),
        media_type="text/event-stream",
        # Prevent buffering in reverse-proxy
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
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
    global eve_db, payload_db, filedata_db
    eve_db = await open_database(EVE_DB_URI)
    payload_db = await open_database(PAYLOAD_DB_URI, bytes)
    filedata_db = await open_database(FILEDATA_DB_URI, bytes)
    yield
    await eve_db.close()
    await payload_db.close()
    await filedata_db.close()


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
    "FILEDATA_DB_URI",
    cast=str,
    default="file:../suricata/output/filedata.sqlar?mode=ro",
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
eve_db = None
payload_db = None
filedata_db = None
templates = Jinja2Templates(directory="templates")
app = Starlette(
    debug=DEBUG,
    routes=[
        Route("/", index),
        Route("/api/events", api_events),
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
