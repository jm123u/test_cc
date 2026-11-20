"""TraceQuarry portable launcher for Windows.

Starts the loopback-only web GUI from the self-contained bundle, picks a free
port, keeps all derived data next to the program, and opens the browser once
the server reports ready.
"""

from __future__ import annotations

import contextlib
import faulthandler
import io
import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import TextIO

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
FIRST_PORT = 8765
PORT_ATTEMPTS = 20
LOG_RETENTION_DAYS = 30


def _writable_directory(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".write-probe-{os.getpid()}"
        probe.write_bytes(b"")
        probe.unlink()
    except OSError:
        return False
    return True


def data_directory() -> Path:
    override = os.environ.get("TRACEQUARRY_DATA_DIR")
    candidates = [Path(override)] if override else []
    candidates.append(BUNDLE_ROOT / "data")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "TraceQuarry" / "data")
    candidates.append(Path.home() / "TraceQuarry" / "data")
    for candidate in candidates:
        if _writable_directory(candidate):
            return candidate.resolve()
    raise SystemExit("TraceQuarry could not find a writable data directory.")


class _Tee(io.TextIOBase):
    """Write console output to the log file as well, so it survives the window."""

    def __init__(self, console: TextIO | None, log: TextIO) -> None:
        self._console = console
        self._log = log

    def write(self, text: str) -> int:
        with contextlib.suppress(Exception):
            self._log.write(text)
        if self._console is not None:
            with contextlib.suppress(Exception):
                self._console.write(text)
        return len(text)

    def flush(self) -> None:
        for stream in (self._log, self._console):
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.flush()


def start_log(data_dir: Path) -> Path | None:
    """Mirror all output, tracebacks, and hard-crash dumps into data/logs."""
    log_dir = data_dir / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        cutoff = time.time() - LOG_RETENTION_DAYS * 86400
        for old in log_dir.glob("tracequarry-*.log"):
            if old.stat().st_mtime < cutoff:
                old.unlink()
        path = log_dir / f"tracequarry-{datetime.now():%Y%m%d}.log"
        log = path.open("a", encoding="utf-8", errors="replace", buffering=1)
    except OSError:
        return None
    log.write(f"\n=== TraceQuarry started {datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
    sys.stdout = _Tee(sys.__stdout__, log)
    sys.stderr = _Tee(sys.__stderr__, log)
    # Native crashes (access violation, stack overflow) bypass Python's
    # traceback machinery; faulthandler still records where each thread was.
    faulthandler.enable(file=log, all_threads=True)
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )
    return path


def disable_quick_edit() -> None:
    """Stop a stray click in the console from freezing the server.

    With QuickEdit on, clicking inside a console window starts a text selection
    and blocks every write to it until a key is pressed, which stalls the job.
    """
    if os.name != "nt":
        return
    with contextlib.suppress(Exception):
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-10)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            enable_extended_flags, enable_quick_edit = 0x0080, 0x0040
            kernel32.SetConsoleMode(
                handle, (mode.value | enable_extended_flags) & ~enable_quick_edit
            )


def _health(port: int, timeout: float = 1.0) -> dict | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(
            f"http://{HOST}:{port}/api/health", timeout=timeout
        ) as response:
            payload = json.load(response)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if os.name == "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind((HOST, port))
        except OSError:
            return False
    return True


def choose_port(preferred: int) -> int:
    for port in range(preferred, preferred + PORT_ATTEMPTS):
        if _port_is_free(port):
            return port
    raise SystemExit(
        f"No free loopback port between {preferred} and {preferred + PORT_ATTEMPTS - 1}."
    )


def _open_when_ready(port: int, open_browser: bool) -> None:
    url = f"http://{HOST}:{port}/"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if _health(port, timeout=0.5) is not None:
            print(f"\n  TraceQuarry is ready:  {url}")
            print(
                "  Keep this window open. Close it (or press Ctrl+C) to stop.\n",
                flush=True,
            )
            if open_browser:
                with contextlib.suppress(Exception):
                    webbrowser.open(url)
            return
        time.sleep(0.2)
    print(f"TraceQuarry did not report ready within 60 seconds; try {url}", flush=True)


def _option_value(argv: list[str], name: str) -> str | None:
    for index, value in enumerate(argv):
        if value == name and index + 1 < len(argv):
            return argv[index + 1]
        if value.startswith(name + "="):
            return value.split("=", 1)[1]
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    open_browser = "--no-browser" not in argv
    argv = [value for value in argv if value != "--no-browser"]
    if "-h" in argv or "--help" in argv:
        from uac_parser.web import main as web_main

        print("TraceQuarry portable launcher. Extra option: --no-browser\n")
        return web_main(argv)

    if os.name == "nt":
        os.system("title TraceQuarry")

    requested_port = _option_value(argv, "--port")
    preferred = int(requested_port) if requested_port else FIRST_PORT
    if requested_port is None:
        existing = _health(preferred)
        if (
            existing is not None
            and existing.get("status") == "ok"
            and "ready" in existing
        ):
            url = f"http://{HOST}:{preferred}/"
            print(f"TraceQuarry is already running at {url}")
            if open_browser:
                webbrowser.open(url)
            return 0
    port = preferred if requested_port else choose_port(preferred)

    data_dir = data_directory()
    evidence_dir = BUNDLE_ROOT / "evidence"
    if not _writable_directory(evidence_dir):
        evidence_dir = data_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

    server_args: list[str] = []
    if requested_port is None:
        server_args += ["--port", str(port)]
    if _option_value(argv, "--work-dir") is None:
        server_args += ["--work-dir", str(data_dir / "web_runs")]
    if _option_value(argv, "--input-root") is None:
        roots = [evidence_dir]
        home = Path.home()
        if home.is_dir():
            roots.append(home)
        for root in roots:
            server_args += ["--input-root", str(root)]

    disable_quick_edit()
    log_path = start_log(data_dir)
    print("TraceQuarry portable")
    print(f"  Data directory:      {data_dir}")
    print(f"  Evidence directory:  {evidence_dir}")
    print(f"  Log file:            {log_path or 'unavailable'}")
    print("  Starting the local server ...", flush=True)

    os.chdir(data_dir)
    threading.Thread(
        target=_open_when_ready, args=(port, open_browser), daemon=True
    ).start()

    from uac_parser.web import main as web_main

    try:
        return web_main(server_args + argv)
    except BaseException as exc:
        if not isinstance(exc, KeyboardInterrupt | SystemExit):
            import traceback

            traceback.print_exc()
        print(f"TraceQuarry stopped: {type(exc).__name__}: {exc}", flush=True)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0) from None
