# Copyright 2026 The OpenSandbox Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Interactive terminal into a sandbox over the execd PTY WebSocket.

Frame protocol is defined in components/execd/PTY.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import IO, Protocol

import click
import httpx
import websockets
from opensandbox.constants import DEFAULT_EXECD_PORT

from opensandbox_cli.client import ClientContext
from opensandbox_cli.utils import handle_errors

# Binary WebSocket frame type bytes, mirroring execd pkg/web/model.
BIN_STDIN = 0x00
BIN_STDOUT = 0x01
BIN_STDERR = 0x02
BIN_REPLAY = 0x03

ReadFn = Callable[[], Awaitable[bytes]]
WriteFn = Callable[[bytes], None]
SizeFn = Callable[[], tuple[int, int]]


class WSDuplex(Protocol):
    """Minimal WebSocket surface used by the relay loop."""

    def send(self, message: bytes | str) -> Awaitable[None]: ...

    def __aiter__(self) -> AsyncIterator[bytes | str]: ...


def _ws_scheme(protocol: str) -> str:
    return "wss" if protocol == "https" else "ws"


def _execd_base(endpoint: str) -> str:
    """Normalize an execd endpoint (``host:port`` or ``host/proxy/path``)."""
    return endpoint.rstrip("/")


def _create_pty_session(
    base_url: str,
    headers: dict[str, str],
    *,
    workdir: str | None,
    timeout: timedelta,
) -> str:
    body: dict[str, str] = {}
    if workdir:
        body["cwd"] = workdir
    try:
        response = httpx.post(
            f"{base_url}/pty",
            headers=headers,
            json=body,
            timeout=timeout.total_seconds(),
        )
    except httpx.HTTPError as exc:
        raise click.ClickException(f"Could not reach the sandbox execd: {exc}") from exc
    if response.status_code != 201:
        detail = response.text.strip() or response.reason_phrase
        raise click.ClickException(
            f"Creating a PTY session failed with HTTP {response.status_code}: {detail}"
        )
    session_id = response.json().get("session_id")
    if not session_id:
        raise click.ClickException("The execd response did not include a session_id.")
    return str(session_id)


def _delete_pty_session(
    base_url: str, headers: dict[str, str], session_id: str, *, timeout: timedelta
) -> None:
    """Best-effort teardown of a finished PTY session; errors are ignored."""
    try:
        httpx.delete(
            f"{base_url}/pty/{session_id}",
            headers=headers,
            timeout=timeout.total_seconds(),
        )
    except httpx.HTTPError:
        pass


@contextmanager
def _raw_mode(fd: int) -> Iterator[None]:
    import termios
    import tty

    old = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _posix_tty_io() -> tuple[ReadFn, WriteFn, SizeFn, int]:
    """Build TTY stdin/stdout/size hooks plus the stdin fd for raw mode."""
    stdin_fd = sys.stdin.fileno()
    stdout: IO[bytes] = sys.stdout.buffer

    async def stdin_read() -> bytes:
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, os.read, stdin_fd, 4096)
        except OSError:
            return b""

    def stdout_write(data: bytes) -> None:
        stdout.write(data)
        stdout.flush()

    def get_size() -> tuple[int, int]:
        size = os.get_terminal_size(stdin_fd)
        return size.columns, size.lines

    return stdin_read, stdout_write, get_size, stdin_fd


async def _pump_stdin(ws: WSDuplex, stdin_read: ReadFn) -> None:
    """Forward local stdin to the PTY as binary frames until EOF or close."""
    while True:
        data = await stdin_read()
        if not data:
            return
        try:
            await ws.send(bytes([BIN_STDIN]) + data)
        except websockets.ConnectionClosed:
            return


async def stream_pty(
    ws: WSDuplex,
    *,
    stdin_read: ReadFn,
    stdout_write: WriteFn,
) -> tuple[int | None, list[str]]:
    """Relay frames; the exit code is ``None`` without an ``exit`` frame."""
    exit_code: int | None = None
    errors: list[str] = []

    async def read_ws() -> None:
        nonlocal exit_code
        async for message in ws:
            if isinstance(message, bytes) and message:
                kind, payload = message[0], message[1:]
                if kind == BIN_REPLAY:
                    if len(payload) <= 8:
                        continue
                    payload = payload[8:]
                if payload and kind in (BIN_STDOUT, BIN_STDERR, BIN_REPLAY):
                    stdout_write(payload)
            elif isinstance(message, str):
                try:
                    frame = json.loads(message)
                except json.JSONDecodeError:
                    continue
                frame_type = frame.get("type")
                if frame_type == "exit":
                    exit_code = int(frame.get("exit_code") or 0)
                    return
                if frame_type == "error":
                    errors.append(str(frame.get("error") or "unknown error"))

    stdin_task = asyncio.create_task(_pump_stdin(ws, stdin_read))
    try:
        # Give the stdin pump a head start before the read loop drains frames.
        await asyncio.sleep(0)
        # A local stdin EOF must not cut the output stream: reap the pump and
        # keep reading until the server sends ``exit`` or closes.
        await read_ws()
    finally:
        stdin_task.cancel()
        await asyncio.gather(stdin_task, return_exceptions=True)
    return exit_code, errors


async def _connect_and_stream(
    ws_url: str,
    headers: dict[str, str],
    *,
    stdin_read: ReadFn,
    stdout_write: WriteFn,
    get_size: SizeFn,
) -> tuple[int | None, list[str]]:
    """Connect to the PTY WebSocket, drive the relay loop, handle resize."""
    async with websockets.connect(ws_url, additional_headers=headers or None) as ws:

        async def send_resize() -> None:
            try:
                cols, rows = get_size()
            except OSError:
                return
            frame = json.dumps({"type": "resize", "cols": cols, "rows": rows})
            try:
                await ws.send(frame)
            except websockets.ConnectionClosed:
                pass

        await send_resize()
        loop = asyncio.get_running_loop()
        has_winch = hasattr(signal, "SIGWINCH")
        if has_winch:
            try:
                loop.add_signal_handler(
                    signal.SIGWINCH,
                    lambda: asyncio.ensure_future(send_resize()),
                )
            except NotImplementedError:  # pragma: no cover - platform guard
                has_winch = False
        try:
            return await stream_pty(ws, stdin_read=stdin_read, stdout_write=stdout_write)
        finally:
            if has_winch:
                loop.remove_signal_handler(signal.SIGWINCH)


def _require_posix_tty() -> None:
    if os.name != "posix":
        raise click.ClickException(
            "osb terminal is only supported on Unix, macOS, and Linux."
        )
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise click.ClickException("osb terminal requires an interactive TTY.")


@click.command(
    "terminal",
    help="Open an interactive terminal into a sandbox via the execd PTY.",
    epilog=(
        "The shell runs inside the sandbox; exit it (or press Ctrl-D) to leave. "
        "The remote exit code becomes this command's exit code."
    ),
)
@click.argument("sandbox_id")
@click.option("-w", "--workdir", default=None, help="Initial working directory.")
@click.pass_obj
@handle_errors
def terminal(
    obj: ClientContext,
    sandbox_id: str,
    workdir: str | None,
) -> None:
    """Open an interactive terminal into a sandbox."""
    _require_posix_tty()

    sandbox = obj.connect_sandbox(sandbox_id)
    try:
        endpoint = sandbox.get_endpoint(DEFAULT_EXECD_PORT)
    finally:
        sandbox.close()

    headers = endpoint.build_request_headers(obj.connection_config)
    protocol = obj.connection_config.protocol
    base = _execd_base(endpoint.endpoint)
    http_base = f"{protocol}://{base}"
    ws_url = f"{_ws_scheme(protocol)}://{base}"

    timeout = timedelta(seconds=obj.resolved_config.get("request_timeout", 30))
    session_id = _create_pty_session(
        http_base, headers, workdir=workdir, timeout=timeout
    )

    stdin_read, stdout_write, get_size, stdin_fd = _posix_tty_io()
    error_write = sys.stderr.buffer.write
    exit_code: int | None = None
    errors: list[str] = []
    teardown = False
    try:
        with _raw_mode(stdin_fd):
            exit_code, errors = asyncio.run(
                _connect_and_stream(
                    f"{ws_url}/pty/{session_id}/ws",
                    headers,
                    stdin_read=stdin_read,
                    stdout_write=stdout_write,
                    get_size=get_size,
                )
            )
        teardown = exit_code is not None
    except websockets.InvalidStatus as exc:
        raise click.ClickException(
            f"The execd refused the terminal connection: {exc}"
        ) from exc
    except (OSError, websockets.WebSocketException) as exc:
        raise click.ClickException(f"Terminal connection failed: {exc}") from exc
    finally:
        # A clean shell exit tears the session down; an interrupted connection
        # leaves it running (shell alive, replay retained) for inspection.
        if teardown:
            _delete_pty_session(http_base, headers, session_id, timeout=timeout)

    for message in errors:
        error_write(message.encode() + b"\n")
        sys.stderr.buffer.flush()
    if exit_code is None:
        raise click.ClickException(
            "The terminal connection closed before the shell exited."
        )
    sys.exit(exit_code)
