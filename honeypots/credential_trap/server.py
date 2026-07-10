#!/usr/bin/env python3
"""
Credential Trap Honeypot Server
================================
A multi-protocol honeypot that listens on FTP (21), Telnet (23), SMTP (25),
and VNC (5900) ports simultaneously. Captures and logs all credential attempts
and connection metadata in a unified JSON format.

Part of the MIRAGE Threat Intelligence Project.
"""

import asyncio
import base64
import json
import logging
import os
import re
import signal
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot/credential_trap.json")
HONEYPOT_NAME = "credential_trap"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

logger = logging.getLogger("credential_trap")
logger.setLevel(logging.INFO)
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
logger.addHandler(_console)

_log_file_handle = None


def _ensure_log_dir() -> None:
    """Create the log directory if it does not exist."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def _get_log_handle():
    """Return (and lazily open) the JSON log file handle."""
    global _log_file_handle
    if _log_file_handle is None or _log_file_handle.closed:
        _ensure_log_dir()
        _log_file_handle = open(LOG_FILE, "a", encoding="utf-8")
    return _log_file_handle


def log_event(
    event_type: str,
    source_ip: str,
    source_port: int,
    protocol: str,
    username: str = "",
    password: str = "",
    raw_input: str = "",
    details: dict | None = None,
) -> None:
    """Write a single JSON event to the log file and stdout."""
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": protocol,
        "honeypot": HONEYPOT_NAME,
        "username": username,
        "password": password,
        "raw_input": raw_input,
        "details": details or {},
    }
    line = json.dumps(record)
    # Write to log file
    fh = _get_log_handle()
    fh.write(line + "\n")
    fh.flush()
    # Echo to stdout for Docker logs
    logger.info(line)


# ---------------------------------------------------------------------------
# FTP handler (port 21)
# ---------------------------------------------------------------------------

async def handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Minimal FTP server that captures USER/PASS credentials."""
    peername = writer.get_extra_info("peername")
    src_ip, src_port = peername[0], peername[1]

    log_event("connection", src_ip, src_port, "ftp", details={"service": "ftp"})

    try:
        writer.write(b"220 FTP Server Ready\r\n")
        await writer.drain()

        username = ""
        while True:
            data = await asyncio.wait_for(reader.readline(), timeout=60)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            log_event("command", src_ip, src_port, "ftp", raw_input=line)

            upper = line.upper()
            if upper.startswith("USER "):
                username = line[5:].strip()
                writer.write(b"331 Password required\r\n")
                await writer.drain()
            elif upper.startswith("PASS "):
                password = line[5:].strip()
                log_event(
                    "login_attempt", src_ip, src_port, "ftp",
                    username=username, password=password, raw_input=line,
                )
                writer.write(b"530 Login incorrect\r\n")
                await writer.drain()
            elif upper.startswith("QUIT"):
                writer.write(b"221 Goodbye\r\n")
                await writer.drain()
                break
            elif upper.startswith("SYST"):
                writer.write(b"215 UNIX Type: L8\r\n")
                await writer.drain()
            elif upper.startswith("FEAT"):
                writer.write(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                await writer.drain()
            else:
                writer.write(b"500 Unknown command\r\n")
                await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as exc:
        logger.error("FTP handler error for %s:%d — %s", src_ip, src_port, exc)
    finally:
        log_event("disconnect", src_ip, src_port, "ftp")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Telnet handler (port 23)
# ---------------------------------------------------------------------------

async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Fake Telnet login prompt that captures credentials."""
    peername = writer.get_extra_info("peername")
    src_ip, src_port = peername[0], peername[1]

    log_event("connection", src_ip, src_port, "telnet", details={"service": "telnet"})

    try:
        writer.write(b"\r\nlogin: ")
        await writer.drain()

        username = ""
        for _ in range(5):
            username_data = await asyncio.wait_for(reader.readline(), timeout=60)
            if not username_data:
                break
            # Strip Telnet IAC negotiations (including subnegotiations)
            cleaned = re.sub(rb'\xff\xfa.*?\xff\xf0', b'', username_data, flags=re.DOTALL)
            cleaned = re.sub(rb'\xff[\xfb-\xfe].', b'', cleaned)
            cleaned = re.sub(rb'\xff[\xf0-\xfa]', b'', cleaned)
            text = cleaned.decode("utf-8", errors="ignore").strip()
            if text:
                username = text
                break

        writer.write(b"Password: ")
        await writer.drain()

        password = ""
        for _ in range(5):
            password_data = await asyncio.wait_for(reader.readline(), timeout=60)
            if not password_data:
                break
            cleaned = re.sub(rb'\xff\xfa.*?\xff\xf0', b'', password_data, flags=re.DOTALL)
            cleaned = re.sub(rb'\xff[\xfb-\xfe].', b'', cleaned)
            cleaned = re.sub(rb'\xff[\xf0-\xfa]', b'', cleaned)
            text = cleaned.decode("utf-8", errors="ignore").strip()
            if text:
                password = text
                break

        log_event(
            "login_attempt", src_ip, src_port, "telnet",
            username=username, password=password,
        )

        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as exc:
        logger.error("Telnet handler error for %s:%d — %s", src_ip, src_port, exc)
    finally:
        log_event("disconnect", src_ip, src_port, "telnet")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SMTP handler (port 25)
# ---------------------------------------------------------------------------

async def handle_smtp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Minimal SMTP server that captures EHLO, MAIL FROM, RCPT TO, and AUTH LOGIN."""
    peername = writer.get_extra_info("peername")
    src_ip, src_port = peername[0], peername[1]

    log_event("connection", src_ip, src_port, "smtp", details={"service": "smtp"})

    try:
        writer.write(b"220 mail.example.com ESMTP\r\n")
        await writer.drain()

        while True:
            data = await asyncio.wait_for(reader.readline(), timeout=60)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            log_event("command", src_ip, src_port, "smtp", raw_input=line)

            upper = line.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                writer.write(
                    b"250-mail.example.com\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n"
                    b"250-STARTTLS\r\n"
                    b"250 OK\r\n"
                )
                await writer.drain()
            elif upper.startswith("MAIL FROM"):
                log_event("command", src_ip, src_port, "smtp", raw_input=line,
                          details={"smtp_command": "MAIL FROM", "value": line})
                writer.write(b"250 OK\r\n")
                await writer.drain()
            elif upper.startswith("RCPT TO"):
                log_event("command", src_ip, src_port, "smtp", raw_input=line,
                          details={"smtp_command": "RCPT TO", "value": line})
                writer.write(b"250 OK\r\n")
                await writer.drain()
            elif upper.startswith("AUTH LOGIN"):
                writer.write(b"334 VXNlcm5hbWU6\r\n")  # Base64 "Username:"
                await writer.drain()

                user_b64 = await asyncio.wait_for(reader.readline(), timeout=30)
                username = ""
                try:
                    username = base64.b64decode(
                        user_b64.decode("utf-8", errors="replace").strip()
                    ).decode("utf-8", errors="replace")
                except Exception:
                    username = user_b64.decode("utf-8", errors="replace").strip()

                writer.write(b"334 UGFzc3dvcmQ6\r\n")  # Base64 "Password:"
                await writer.drain()

                pass_b64 = await asyncio.wait_for(reader.readline(), timeout=30)
                password = ""
                try:
                    password = base64.b64decode(
                        pass_b64.decode("utf-8", errors="replace").strip()
                    ).decode("utf-8", errors="replace")
                except Exception:
                    password = pass_b64.decode("utf-8", errors="replace").strip()

                log_event(
                    "login_attempt", src_ip, src_port, "smtp",
                    username=username, password=password,
                    raw_input="AUTH LOGIN",
                )
                writer.write(b"535 Authentication failed\r\n")
                await writer.drain()
            elif upper.startswith("DATA"):
                writer.write(b"354 Start mail input\r\n")
                await writer.drain()
                # Read until lone dot
                body_lines = []
                while True:
                    d = await asyncio.wait_for(reader.readline(), timeout=60)
                    if not d:
                        break
                    d_line = d.decode("utf-8", errors="replace").strip()
                    if d_line == ".":
                        break
                    body_lines.append(d_line)
                log_event("command", src_ip, src_port, "smtp", raw_input="DATA",
                          details={"body_lines": len(body_lines)})
                writer.write(b"250 OK\r\n")
                await writer.drain()
            elif upper.startswith("QUIT"):
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            elif upper.startswith("STARTTLS"):
                writer.write(b"454 TLS not available\r\n")
                await writer.drain()
            elif upper.startswith("RSET"):
                writer.write(b"250 OK\r\n")
                await writer.drain()
            elif upper.startswith("NOOP"):
                writer.write(b"250 OK\r\n")
                await writer.drain()
            else:
                writer.write(b"502 Command not implemented\r\n")
                await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as exc:
        logger.error("SMTP handler error for %s:%d — %s", src_ip, src_port, exc)
    finally:
        log_event("disconnect", src_ip, src_port, "smtp")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# VNC handler (port 5900)
# ---------------------------------------------------------------------------

async def handle_vnc(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Fake VNC server that performs the protocol handshake and logs attempts."""
    peername = writer.get_extra_info("peername")
    src_ip, src_port = peername[0], peername[1]

    log_event("connection", src_ip, src_port, "vnc", details={"service": "vnc"})

    try:
        # Send VNC protocol version
        writer.write(b"RFB 003.008\n")
        await writer.drain()

        # Read client response (12 bytes: "RFB xxx.yyy\n")
        client_version = await asyncio.wait_for(reader.read(12), timeout=30)
        version_str = client_version.decode("utf-8", errors="replace").strip() if client_version else ""

        log_event(
            "command", src_ip, src_port, "vnc",
            raw_input=version_str,
            details={"client_version": version_str},
        )

        if not client_version:
            return

        # Send security types: 1 type available — VNC Authentication (type 2)
        writer.write(b"\x01\x02")
        await writer.drain()

        # Read chosen security type (1 byte)
        sec_type_data = await asyncio.wait_for(reader.read(1), timeout=30)
        if sec_type_data:
            sec_type = int.from_bytes(sec_type_data, "big")
            log_event(
                "command", src_ip, src_port, "vnc",
                raw_input=f"security_type={sec_type}",
                details={"security_type": sec_type},
            )

            if sec_type == 2:
                # VNC Authentication — send 16-byte challenge
                challenge = os.urandom(16)
                writer.write(challenge)
                await writer.drain()

                # Read 16-byte response
                response = await asyncio.wait_for(reader.read(16), timeout=30)
                log_event(
                    "login_attempt", src_ip, src_port, "vnc",
                    raw_input="vnc_auth_response",
                    details={
                        "challenge_hex": challenge.hex(),
                        "response_hex": response.hex() if response else "",
                    },
                )

            # Send authentication failure
            writer.write(b"\x00\x00\x00\x01")  # SecurityResult: failed
            await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as exc:
        logger.error("VNC handler error for %s:%d — %s", src_ip, src_port, exc)
    finally:
        log_event("disconnect", src_ip, src_port, "vnc")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_servers: list[asyncio.Server] = []


async def start_servers() -> None:
    """Start all protocol handlers on their respective ports."""
    handlers = [
        (handle_ftp, 21, "FTP"),
        (handle_telnet, 23, "Telnet"),
        (handle_smtp, 25, "SMTP"),
        (handle_vnc, 5900, "VNC"),
    ]

    for handler, port, name in handlers:
        try:
            server = await asyncio.start_server(handler, "0.0.0.0", port)
            _servers.append(server)
            logger.info("Credential Trap — %s listening on port %d", name, port)
        except OSError as exc:
            logger.error("Failed to bind %s on port %d: %s", name, port, exc)

    if not _servers:
        logger.error("No servers could be started — exiting")
        sys.exit(1)


async def shutdown() -> None:
    """Gracefully shut down all servers."""
    logger.info("Shutting down Credential Trap honeypot …")
    for server in _servers:
        server.close()
    for server in _servers:
        await server.wait_closed()
    # Close the log file
    global _log_file_handle
    if _log_file_handle and not _log_file_handle.closed:
        _log_file_handle.close()


def _handle_signal(sig, _frame) -> None:
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    logger.info("Received signal %s — shutting down", signal.Signals(sig).name)
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown())
    loop.stop()


def main() -> None:
    """Entry point — wire up signals and start the event loop."""
    # Register signal handlers
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(start_servers())
        logger.info("Credential Trap honeypot is running — all ports active")
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(shutdown())
        loop.close()


if __name__ == "__main__":
    main()
