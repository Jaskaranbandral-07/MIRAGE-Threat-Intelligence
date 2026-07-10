#!/usr/bin/env python3
"""
ADBHoney — Android Debug Bridge Honeypot Server
==================================================
A Python asyncio server that mimics an exposed Android Debug Bridge (ADB)
service. Implements the ADB protocol handshake and captures shell commands
that attackers attempt to execute (common in IoT botnet campaigns).

Part of the MIRAGE Threat Intelligence Project.

ADB Protocol Reference:
  - Messages are 24 bytes: command(4) + arg0(4) + arg1(4) + data_length(4) +
    data_crc32(4) + magic(4), followed by `data_length` bytes of payload.
  - Key commands: CNXN (connect), OPEN (open stream), WRTE (write data),
    CLSE (close stream), OKAY (acknowledgement).
"""

import asyncio
import json
import logging
import os
import signal
import struct
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot/adbhoney.json")
HONEYPOT_NAME = "adbhoney"
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", 5555))

# ADB protocol constants
ADB_HEADER_SIZE = 24
CMD_CNXN = 0x4E584E43  # 'CNXN'
CMD_OPEN = 0x4E45504F  # 'OPEN'
CMD_WRTE = 0x45545257  # 'WRTE'
CMD_CLSE = 0x45534C43  # 'CLSE'
CMD_OKAY = 0x59414B4F  # 'OKAY'
CMD_AUTH = 0x48545541  # 'AUTH'

# ADB version and max data
ADB_VERSION = 0x01000000
ADB_MAXDATA = 4096

# Device banner sent during handshake
DEVICE_BANNER = b"device::ro.product.name=mako;ro.product.model=Nexus 4;ro.product.device=mako;"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

logger = logging.getLogger("adbhoney")
logger.setLevel(logging.INFO)
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
logger.addHandler(_console)

_log_file_handle = None


def _ensure_log_dir() -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def _get_log_handle():
    global _log_file_handle
    if _log_file_handle is None or _log_file_handle.closed:
        _ensure_log_dir()
        _log_file_handle = open(LOG_FILE, "a", encoding="utf-8")
    return _log_file_handle


def log_event(
    event_type: str,
    source_ip: str,
    source_port: int,
    raw_input: str = "",
    details: dict | None = None,
) -> None:
    """Write a JSON event to the log file and stdout."""
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": "adb",
        "honeypot": HONEYPOT_NAME,
        "username": "",
        "password": "",
        "raw_input": raw_input,
        "details": details or {},
    }
    line = json.dumps(record)
    fh = _get_log_handle()
    fh.write(line + "\n")
    fh.flush()
    logger.info(line)


# ---------------------------------------------------------------------------
# ADB protocol helpers
# ---------------------------------------------------------------------------

def _cmd_name(cmd: int) -> str:
    """Return a human-readable name for an ADB command code."""
    names = {CMD_CNXN: "CNXN", CMD_OPEN: "OPEN", CMD_WRTE: "WRTE", CMD_CLSE: "CLSE",
             CMD_OKAY: "OKAY", CMD_AUTH: "AUTH"}
    return names.get(cmd, f"0x{cmd:08X}")


def _make_message(cmd: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    """Construct an ADB protocol message (header + payload)."""
    data_length = len(data)
    # Simple checksum: sum of all bytes in data
    data_crc = sum(data) & 0xFFFFFFFF
    magic = cmd ^ 0xFFFFFFFF
    header = struct.pack("<IIIIII", cmd, arg0, arg1, data_length, data_crc, magic)
    return header + data


async def _read_message(reader: asyncio.StreamReader) -> tuple[int, int, int, bytes] | None:
    """
    Read one ADB message from the stream.

    Returns (command, arg0, arg1, payload) or None on disconnect.
    """
    header = await reader.readexactly(ADB_HEADER_SIZE)
    if len(header) < ADB_HEADER_SIZE:
        return None

    cmd, arg0, arg1, data_length, data_crc, magic = struct.unpack("<IIIIII", header)

    # Basic sanity: magic should be cmd ^ 0xFFFFFFFF
    if magic != (cmd ^ 0xFFFFFFFF):
        return None

    payload = b""
    if data_length > 0:
        payload = await reader.readexactly(data_length)

    return cmd, arg0, arg1, payload


# ---------------------------------------------------------------------------
# ADB client handler
# ---------------------------------------------------------------------------

async def handle_adb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle a single ADB client connection."""
    peername = writer.get_extra_info("peername")
    src_ip, src_port = peername[0], peername[1]

    log_event("connection", src_ip, src_port, details={"service": "adb"})

    local_id_counter = 1  # Track local stream IDs

    try:
        # Send CNXN handshake
        cnxn_data = DEVICE_BANNER + b"\x00"
        cnxn_msg = _make_message(CMD_CNXN, ADB_VERSION, ADB_MAXDATA, cnxn_data)
        writer.write(cnxn_msg)
        await writer.drain()

        while True:
            try:
                result = await asyncio.wait_for(_read_message(reader), timeout=120)
            except asyncio.IncompleteReadError:
                break

            if result is None:
                break

            cmd, arg0, arg1, payload = result
            payload_str = payload.decode("utf-8", errors="replace").rstrip("\x00").strip()

            log_event(
                "command", src_ip, src_port,
                raw_input=payload_str,
                details={
                    "adb_command": _cmd_name(cmd),
                    "arg0": arg0,
                    "arg1": arg1,
                },
            )

            if cmd == CMD_CNXN:
                # Client sending its own CNXN — acknowledge (already sent ours)
                log_event(
                    "command", src_ip, src_port,
                    raw_input=payload_str,
                    details={"adb_command": "CNXN", "client_banner": payload_str},
                )

            elif cmd == CMD_OPEN:
                # Client wants to open a stream (usually "shell:...")
                remote_id = arg0
                local_id = local_id_counter
                local_id_counter += 1

                log_event(
                    "command", src_ip, src_port,
                    raw_input=payload_str,
                    details={
                        "adb_command": "OPEN",
                        "stream_destination": payload_str,
                        "remote_id": remote_id,
                        "local_id": local_id,
                    },
                )

                # Send OKAY to accept the stream
                okay_msg = _make_message(CMD_OKAY, local_id, remote_id)
                writer.write(okay_msg)
                await writer.drain()

                # If it's a shell command, send a fake response
                if payload_str.startswith("shell:"):
                    shell_cmd = payload_str[6:]
                    log_event(
                        "command", src_ip, src_port,
                        raw_input=shell_cmd,
                        details={"adb_command": "SHELL", "shell_command": shell_cmd},
                    )

                    # Send a plausible empty response and close
                    fake_output = b""
                    if "id" in shell_cmd:
                        fake_output = b"uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats)\n"
                    elif "getprop" in shell_cmd:
                        fake_output = b"[ro.build.display.id]: [JDQ39]\n[ro.build.version.sdk]: [16]\n"
                    elif "uname" in shell_cmd:
                        fake_output = b"Linux localhost 3.4.0-perf-g7ce11cd #1 SMP PREEMPT armv7l\n"

                    if fake_output:
                        wrte_msg = _make_message(CMD_WRTE, local_id, remote_id, fake_output)
                        writer.write(wrte_msg)
                        await writer.drain()

                    # Close the stream
                    clse_msg = _make_message(CMD_CLSE, local_id, remote_id)
                    writer.write(clse_msg)
                    await writer.drain()

            elif cmd == CMD_WRTE:
                # Client writing data to an open stream
                log_event(
                    "command", src_ip, src_port,
                    raw_input=payload_str,
                    details={
                        "adb_command": "WRTE",
                        "data": payload_str,
                        "remote_id": arg0,
                        "local_id": arg1,
                    },
                )
                # Acknowledge the write
                okay_msg = _make_message(CMD_OKAY, arg1, arg0)
                writer.write(okay_msg)
                await writer.drain()

            elif cmd == CMD_CLSE:
                # Client closing a stream
                clse_msg = _make_message(CMD_CLSE, arg1, arg0)
                writer.write(clse_msg)
                await writer.drain()

            elif cmd == CMD_AUTH:
                # Auth request — we don't require auth, just send CNXN again
                cnxn_msg = _make_message(CMD_CNXN, ADB_VERSION, ADB_MAXDATA, cnxn_data)
                writer.write(cnxn_msg)
                await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        logger.error("ADB handler error for %s:%d — %s", src_ip, src_port, exc)
    finally:
        log_event("disconnect", src_ip, src_port)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_server: asyncio.Server | None = None


async def start_server() -> None:
    """Start the ADB honeypot server."""
    global _server
    _server = await asyncio.start_server(handle_adb, "0.0.0.0", LISTEN_PORT)
    logger.info("ADBHoney listening on port %d", LISTEN_PORT)


async def shutdown() -> None:
    """Gracefully shut down the server."""
    logger.info("Shutting down ADBHoney …")
    if _server:
        _server.close()
        await _server.wait_closed()
    global _log_file_handle
    if _log_file_handle and not _log_file_handle.closed:
        _log_file_handle.close()


def _handle_signal(sig, _frame):
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    logger.info("Received signal %s — shutting down ADBHoney", signal.Signals(sig).name)
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown())
    loop.stop()


def main():
    """Entry point — start the ADB honeypot."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(start_server())
        logger.info("ADBHoney is running")
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(shutdown())
        loop.close()


if __name__ == "__main__":
    main()
