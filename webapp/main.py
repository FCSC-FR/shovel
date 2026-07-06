#!/usr/bin/env python3
# Copyright (C) 2023-2024  ANSSI
# Copyright (C) 2025-2026  A. Iooss
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import base64
import contextlib
import json
from pathlib import Path

import asyncpg
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates


def row_flatten_json(row: dict) -> dict:
    metadata = json.loads(row.pop("json_metadata", "{}") or "{}")
    extra_data = json.loads(row.pop("json_extra_data", "{}") or "{}")
    tags = json.loads(row.pop("json_tags", "{}") or "{}")
    return row | metadata | extra_data | tags


async def index(_):
    return FileResponse("static/index.html")


async def api_filedata_get(request):
    assert db is not None
    sha256 = request.path_params["sha256"]

    async with db.acquire() as con:
        row = await con.fetchrow(
            "SELECT sz, data FROM filedata WHERE name = $1",
            sha256,
        )
    if not row:
        raise HTTPException(404)
    data = row["data"]
    extra_header = {"Content-Encoding": "deflate"} if row["sz"] != len(data) else {}
    return Response(data, headers={"Cache-Control": "max-age=86400"} | extra_header)


async def api_flow_list(request):
    assert db is not None
    ts_to = request.query_params.get("to", str(int(1e16)))
    services = request.query_params.getlist("service")
    app_proto = request.query_params.get("app_proto")
    search = request.query_params.get("search")
    tags_require = request.query_params.getlist("tag_require")
    tags_deny = request.query_params.getlist("tag_deny")
    if not ts_to.isnumeric():
        raise HTTPException(400)

    # Search flows containing search pattern
    search_fid = []
    if search:
        # Collect all flows id with raw payload matching search
        async with db.acquire() as con:
            rows = await con.fetch(
                "SELECT flow_id FROM rawdata WHERE ENCODE(data, 'escape') LIKE $1",
                f"%{search}%",
            )
        search_fid = [r["flow_id"] for r in rows]

        # Collect all flows id with uncompressed filedata matching search
        async with db.acquire() as con:
            rows = await con.fetch(
                "SELECT flow_id FROM \"other-event\" JOIN filedata ON filedata.name = extra_data->>'sha256' "
                "WHERE event_type='fileinfo' AND LENGTH(data) = sz AND ENCODE(data, 'escape') LIKE $1",
                f"%{search}%",
            )
        search_fid += [r["flow_id"] for r in rows]

    # Handle the filtering of flows related to no services
    services_inverse = services == ["!"]
    if services == ["!"]:
        services = sum(CTF_CONFIG["services"].values(), [])

    # To get all flows matching all chosen tag, a relational division is used
    query = """
        SELECT id, ts_start, ts_end, dest_ip, dest_port, app_proto, json(metadata) AS json_metadata,
            (SELECT json_build_object('tags', json_agg(r)) AS json_tags FROM (SELECT tag, color, COUNT(*) as count FROM alert WHERE flow_id = flow.id GROUP BY tag, color) r)
        FROM flow
        WHERE ts_start <= $1
            AND ($2::text IS NULL OR $2::text = app_proto)
            AND (ARRAY_LENGTH($3::text[], 1) IS NULL OR flow.id IN (SELECT flow_id FROM alert WHERE tag = ANY($3::text[]) GROUP BY flow_id HAVING COUNT(DISTINCT tag) = ARRAY_LENGTH($3::text[], 1)))
            AND (ARRAY_LENGTH($4::text[], 1) IS NULL OR NOT EXISTS (SELECT 1 FROM alert WHERE flow_id = flow.id AND alert.tag = ANY($4::text[])))
            AND (ARRAY_LENGTH($5::bigint[], 1) IS NULL OR flow.id = ANY($5::bigint[]))
            AND (
                (NOT $7::boolean AND (ARRAY_LENGTH($6::text[], 1) IS NULL OR (src_ip||':'||src_port) = ANY($6::text[]) OR (dest_ip||':'||dest_port) = ANY($6::text[])))
                OR ($7::boolean AND NOT ((src_ip||':'||src_port) = ANY($6::text[]) OR (dest_ip||':'||dest_port) = ANY($6::text[])))
            )
        ORDER BY ts_start DESC LIMIT 100
    """
    async with db.acquire() as con:
        rows = await con.fetch(
            query,
            int(ts_to),
            "failed" if app_proto == "raw" else app_proto,
            tags_require,
            tags_deny,
            search_fid,
            services,
            services_inverse,
        )
    flows = [row_flatten_json(dict(row)) for row in rows]
    return JSONResponse({"flows": flows})


async def api_flow_get(request):
    assert db is not None
    flow_id = request.path_params["flow_id"]

    # Query flow from database
    async with db.acquire() as con:
        row = await con.fetchrow(
            (
                "SELECT id, ts_start, ts_end, src_ip, src_port, dest_ip, dest_port, "
                "proto, app_proto, json(metadata) AS json_metadata, extra_data AS json_extra_data FROM flow WHERE id = $1"
            ),
            flow_id,
        )
    if not row:
        raise HTTPException(404)
    flow = row_flatten_json(dict(row))
    result: dict[str, list | dict] = {"flow": flow}

    # Get associated events
    async with db.acquire() as con:
        rows = await con.fetch(
            'SELECT event_type, extra_data AS json_extra_data, COUNT(*) AS count FROM "other-event" WHERE flow_id = $1 GROUP BY event_type, extra_data ORDER BY MIN(timestamp)',
            flow_id,
        )
    for row in rows:
        result[row["event_type"]] = result.get(row["event_type"], []) + [
            row_flatten_json(dict(row))
        ]

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_flow_pcap_get(request):
    assert db is not None
    flow_id = request.path_params["flow_id"]

    # Query flow start timestamp from database
    async with db.acquire() as con:
        row = await con.fetchrow("SELECT ts_start FROM flow WHERE id = $1", flow_id)
    if not row:
        raise HTTPException(404)
    flow_us = row["ts_start"] // 1000

    # Serve corresponding pcap, found using timestamp
    path = None
    for pcap_path in sorted(Path("../output_suricata/pcaps/").glob("*.*")):
        pcap_us = int(pcap_path.name.replace(".lz4", "").rsplit(".", 1)[-1])
        if pcap_us * 1000 > flow_us:
            break  # take previous one
        path = pcap_path
    if path is None:
        raise HTTPException(404)
    return Response(
        path.open("rb").read(),  # cache before sending as file might change
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


async def api_flow_raw_get(request):
    assert db is not None
    flow_id = request.path_params["flow_id"]

    # Get associated raw data
    async with db.acquire() as con:
        rows = await con.fetch(
            "SELECT direction, data FROM rawdata WHERE flow_id = $1 ORDER BY count",
            flow_id,
        )
    result = []
    for r in rows:
        data = base64.b64encode(r["data"]).decode()
        result.append({"direction": r["direction"], "data": data})

    return JSONResponse(result, headers={"Cache-Control": "max-age=86400"})


async def api_replay_http(request):
    assert db is not None
    flow_id = request.path_params["flow_id"]

    # Get HTTP events
    async with db.acquire() as con:
        rows = await con.fetch(
            "SELECT flow_id, extra_data AS json_extra_data FROM \"other-event\" WHERE flow_id = $1 AND event_type = 'http' ORDER BY timestamp",
            flow_id,
        )

    # For each HTTP request, load client payload if it exists
    data = []
    for tx_id, row in enumerate(rows):
        req = row_flatten_json(dict(row))
        req["rq_content"] = None
        if req["http_method"] in ["POST"]:
            async with db.acquire() as con:
                row = await con.fetchrow(
                    "SELECT sz, data FROM \"other-event\" JOIN filedata ON filedata.name = extra_data->>'sha256' WHERE flow_id = $1 AND event_type = 'fileinfo' AND (extra_data->>'tx_id')::bigint = $2 ORDER BY timestamp",
                    flow_id,
                    tx_id,
                )
            if not row:
                raise HTTPException(404)
            d, sz = row["data"], row["sz"]
            req["rq_content"] = f"[TODO] {sz} bytes".encode() if sz != len(d) else d
        data.append(req)

    context = {"request": request, "data": data, "services": CTF_CONFIG["services"]}
    return templates.TemplateResponse(
        "http-replay.py.jinja2", context, media_type="text/plain"
    )


async def api_replay_raw(request):
    assert db is not None
    flow_id = request.path_params["flow_id"]

    # Get flow event
    async with db.acquire() as con:
        flow_event = await con.fetchrow(
            "SELECT dest_ip, dest_port, proto FROM flow WHERE id = $1",
            flow_id,
        )
    if not flow_event:
        raise HTTPException(404)
    data = {
        "flow_id": flow_id,
        "ip": flow_event["dest_ip"],
        "port": flow_event["dest_port"],
        "proto": flow_event["proto"],
    }

    # Get associated raw data
    async with db.acquire() as con:
        rows = await con.fetch(
            "SELECT direction, data FROM rawdata WHERE flow_id = $1 ORDER BY count",
            flow_id,
        )
    if not rows:
        raise HTTPException(404)

    # Load files
    data["raw_data"] = []
    for row in rows:
        sc, raw_data = row["direction"], row["data"]
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
    assert db is not None
    last_ts_minmax, last_prs, last_tags = (-1, -1), None, None
    config_sent = False
    try:
        while True:
            # Get first and last flow timestamp, application protocols and tags
            async with db.acquire() as con:
                row = await con.fetchrow(
                    "SELECT MIN(ts_start) as min, MAX(ts_start) as max FROM flow"
                )
                ts_minmax = row["min"], row["max"]
                rows = await con.fetch("SELECT app_proto FROM app_protos")
                prs = [r["app_proto"] for r in rows if r["app_proto"] != "failed"]
                rows = await con.fetch("SELECT tag, color FROM tags")
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


@contextlib.asynccontextmanager
async def lifespan(app):
    """
    Open databases on startup.
    Close databases on exit.
    """
    global db
    while True:
        try:
            db = await asyncpg.create_pool(DATABASE_URL)
        except ConnectionRefusedError as e:
            print(f"Unable to open database: {e}", flush=True)
            await asyncio.sleep(1)
            continue
        break
    yield
    await db.close()


# Load configuration from environment variables, then .env file
config = Config("../.env")
DEBUG = config("DEBUG", cast=bool, default=False)
DATABASE_URL = config(
    "DATABASE_URL", cast=str, default="postgres://shovel:@localhost/shovel"
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
db: None | asyncpg.Pool = None
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
        Route("/api/flow/{flow_id:int}/replay-http", api_replay_http),
        Route("/api/flow/{flow_id:int}/replay-raw", api_replay_raw),
        Mount("/static", StaticFiles(directory="static")),
    ],
    lifespan=lifespan,
)
