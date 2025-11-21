import asyncio
import io
import logging
import sys
from pathlib import Path
from typing import AsyncIterable, BinaryIO, Iterable

PCAP_HEADER_SIZE = 24

log = logging.getLogger(__name__)


async def pipe_data(reader: asyncio.StreamReader, fout: BinaryIO, skip: int = 0):
    """Pipe data from reader to fout, skipping initial bytes if specified."""
    while True:
        chunk = await reader.read(io.DEFAULT_BUFFER_SIZE)
        if not chunk:
            break
        if skip:
            chunk = chunk[skip:]
            skip = 0
        fout.write(chunk)


async def stream_pcaps(pcaps: Iterable[str | Path], fout: BinaryIO) -> None:
    """Stream multiple pcap files to the given output file-like object."""
    for i, pcap in enumerate(pcaps):
        log.debug(pcap)
        match Path(pcap).suffix.lower():
            case ".lz4":
                args = ["lz4cat", str(pcap)]
            case ".gz":
                args = ["zcat", str(pcap)]
            case ".pcap" | ".pcapng":
                args = ["cat", str(pcap)]
            case _:
                raise ValueError(f"Unknown file extension for pcap: {pcap}")

        log.debug("stream_pcaps args=%r", args)
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
        )
        skip = PCAP_HEADER_SIZE if i > 0 else 0
        async with asyncio.TaskGroup() as tg:
            stdout_task = tg.create_task(pipe_data(process.stdout, fout, skip=skip))

        log.debug("finished stream_pcaps")


async def stream_pcaps_with_bpf(
    pcaps: list[str | Path], bpf_filter: str
) -> AsyncIterable[bytes]:
    """Stream pcap data through tcpdump with BPF filter applied."""
    # Run tcpdump with reading from stdin and writing to stdout using the BPF filter
    args = ["tcpdump", "-r", "-", "-w", "-", bpf_filter]
    log.debug("stream_pcaps_with_bpf args=%r", args)
    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )

    # create task to stream pcaps into tcpdump's stdin
    stream_task = asyncio.create_task(stream_pcaps(pcaps, process.stdin))
    stream_task.add_done_callback(lambda t: process.stdin.close())

    # read tcpdump's stdout and yield chunks
    while True:
        chunk = await process.stdout.read(io.DEFAULT_BUFFER_SIZE)
        if not chunk:
            break
        yield chunk
