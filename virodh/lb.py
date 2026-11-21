"""
Minimal TCP load balancer (least-connections) for running several gateway processes on Windows.

Why it exists: with `uvicorn --workers N` on Windows, all workers share one listening socket, and a worker that
loses the race for a new connection can block inside accept() until the next connection arrives — freezing that
worker's keep-alive clients (observed and confirmed with stack dumps). Linux (fork) and Docker replicas behind
nginx are not affected. On Windows we instead run N independent single-process gateways on internal ports and
balance connections across them here.

Connection-level balancing: a keep-alive connection stays on one backend; SSE and large bodies pass through
untouched. Backends that refuse connections are skipped for a few seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

log = logging.getLogger("virodh.lb")
BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nRetry-After: 2\r\nConnection: close\r\n"
    b"Content-Length: 105\r\n\r\n"
    b'{"error":{"message":"No gateway worker is available; retry shortly.","type":"server_error","code":"no_backend"}}'
)


class Backend:
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port
        self.active = 0
        self.down_until = 0.0
        self.total = 0

    def __repr__(self) -> str:
        return f"{self.host}:{self.port}"


class Balancer:
    def __init__(self, backends: list[tuple[str, int]], connect_timeout: float = 3.0):
        self.backends = [Backend(h, p) for h, p in backends]
        self.connect_timeout = connect_timeout

    def _order(self) -> list[Backend]:
        now = time.monotonic()
        up = [b for b in self.backends if b.down_until <= now]
        down = [b for b in self.backends if b.down_until > now]
        return sorted(up, key=lambda b: (b.active, b.total)) + down  # least connections first; down ones last resort

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream = chosen = None
        for b in self._order():
            b.active += 1  # reserve BEFORE awaiting the connect: a burst of simultaneous
            b.total += 1  # connections must not all see the same "least loaded" backend
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(b.host, b.port), self.connect_timeout)
                chosen = b
                break
            except (TimeoutError, OSError):
                b.active -= 1
                b.down_until = time.monotonic() + 5
                log.warning("backend %s unavailable", b)
        if upstream is None:
            try:
                writer.write(BUSY)
                await writer.drain()
            finally:
                writer.close()
            return
        br, bw = upstream
        try:
            await asyncio.gather(_pipe(reader, bw), _pipe(br, writer))
        finally:
            chosen.active -= 1
            for w in (bw, writer):
                with contextlib.suppress(Exception):
                    w.close()

    async def serve(self, host: str, port: int) -> None:
        server = await asyncio.start_server(self.handle, host, port, backlog=512)
        log.info("Virodh load balancer on %s:%s → %s", host, port, self.backends)
        async with server:
            await server.serve_forever()


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            if dst.can_write_eof():
                dst.write_eof()  # half-close: the other direction may still be sending
        except (OSError, RuntimeError):
            pass
