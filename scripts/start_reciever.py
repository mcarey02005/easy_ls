#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8080

WORKING_DIRECTORY = Path.cwd()
OUTPUT_FILE = WORKING_DIRECTORY / "response"
TEMP_DIRECTORY = WORKING_DIRECTORY / ".receiver_chunks"

MAX_CONTROL_BODY_SIZE = 64 * 1024
MAX_CHUNK_BODY_SIZE = 1024 * 1024
TRANSFER_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")

transfers: dict[str, dict[str, int]] = {}
transfer_lock = threading.Lock()


def send_json(
    handler: BaseHTTPRequestHandler,
    status: int,
    payload: dict[str, Any],
) -> None:
    body = json.dumps(payload).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def validate_transfer_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("transferId must be a string")

    if not TRANSFER_ID_PATTERN.fullmatch(value):
        raise ValueError("Invalid transferId")

    return value


class ReceiverHandler(BaseHTTPRequestHandler):
    server_version = "RawChunkReceiver/1.0"

    def do_POST(self) -> None:
        try:
            parsed_url = urlparse(self.path)

            if parsed_url.path == "/start":
                self.handle_start()
            elif parsed_url.path == "/chunk":
                self.handle_chunk(parsed_url.query)
            elif parsed_url.path == "/complete":
                self.handle_complete()
            else:
                send_json(self, 404, {"error": "Unknown endpoint"})

        except ValueError as error:
            send_json(self, 400, {"error": str(error)})
        except Exception as error:
            print(f"Server error: {error}")
            send_json(self, 500, {"error": "Internal server error"})

    def read_body(self, maximum_size: int) -> bytes:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error

        if content_length < 0:
            raise ValueError("Invalid Content-Length")

        if content_length > maximum_size:
            raise ValueError("Request body is too large")

        body = self.rfile.read(content_length)

        if len(body) != content_length:
            raise ValueError("Incomplete request body")

        return body

    def read_json_body(self) -> dict[str, Any]:
        raw_body = self.read_body(MAX_CONTROL_BODY_SIZE)

        if not raw_body:
            raise ValueError("Request body is empty")

        try:
            value = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Invalid JSON request body") from error

        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")

        return value

    def handle_start(self) -> None:
        request = self.read_json_body()

        transfer_id = validate_transfer_id(request.get("transferId"))
        total_chunks = request.get("totalChunks")
        total_bytes = request.get("totalBytes")

        if not isinstance(total_chunks, int) or total_chunks < 1:
            raise ValueError("totalChunks must be a positive integer")

        if not isinstance(total_bytes, int) or total_bytes < 1:
            raise ValueError("totalBytes must be a positive integer")

        transfer_directory = TEMP_DIRECTORY / transfer_id

        with transfer_lock:
            if transfer_directory.exists():
                shutil.rmtree(transfer_directory)

            transfer_directory.mkdir(parents=True)

            transfers[transfer_id] = {
                "total_chunks": total_chunks,
                "total_bytes": total_bytes,
            }

        print(
            f"Started {transfer_id}: "
            f"{total_bytes} bytes in {total_chunks} chunks"
        )

        send_json(
            self,
            200,
            {
                "status": "ready",
                "transferId": transfer_id,
            },
        )

    def handle_chunk(self, query_string: str) -> None:
        parameters = parse_qs(query_string)

        transfer_values = parameters.get("transferId")
        index_values = parameters.get("chunkIndex")

        if not transfer_values:
            raise ValueError("Missing transferId")

        if not index_values:
            raise ValueError("Missing chunkIndex")

        transfer_id = validate_transfer_id(transfer_values[0])

        try:
            chunk_index = int(index_values[0])
        except ValueError as error:
            raise ValueError("chunkIndex must be an integer") from error

        with transfer_lock:
            transfer = transfers.get(transfer_id)

        if transfer is None:
            raise ValueError("Unknown transferId")

        total_chunks = transfer["total_chunks"]

        if chunk_index < 1 or chunk_index > total_chunks:
            raise ValueError("chunkIndex is outside the expected range")

        chunk = self.read_body(MAX_CHUNK_BODY_SIZE)

        transfer_directory = TEMP_DIRECTORY / transfer_id
        chunk_path = transfer_directory / f"{chunk_index:08d}.part"
        temporary_path = transfer_directory / f"{chunk_index:08d}.tmp"

        temporary_path.write_bytes(chunk)
        temporary_path.replace(chunk_path)

        print(
            f"Received chunk {chunk_index}/{total_chunks}: "
            f"{len(chunk)} bytes"
        )

        send_json(
            self,
            200,
            {
                "status": "received",
                "chunkIndex": chunk_index,
            },
        )

    def handle_complete(self) -> None:
        request = self.read_json_body()
        transfer_id = validate_transfer_id(request.get("transferId"))

        with transfer_lock:
            transfer = transfers.get(transfer_id)

        if transfer is None:
            raise ValueError("Unknown transferId")

        total_chunks = transfer["total_chunks"]
        expected_bytes = transfer["total_bytes"]
        transfer_directory = TEMP_DIRECTORY / transfer_id

        missing_chunks = [
            index
            for index in range(1, total_chunks + 1)
            if not (
                transfer_directory / f"{index:08d}.part"
            ).is_file()
        ]

        if missing_chunks:
            raise ValueError(
                f"Missing chunks: {missing_chunks[:20]}"
            )

        temporary_output = WORKING_DIRECTORY / "response.tmp"
        digest = hashlib.sha256()
        actual_bytes = 0

        with temporary_output.open("wb") as output:
            for index in range(1, total_chunks + 1):
                chunk_path = (
                    transfer_directory / f"{index:08d}.part"
                )

                with chunk_path.open("rb") as chunk_file:
                    while True:
                        block = chunk_file.read(1024 * 1024)

                        if not block:
                            break

                        output.write(block)
                        digest.update(block)
                        actual_bytes += len(block)

        if actual_bytes != expected_bytes:
            temporary_output.unlink(missing_ok=True)
            raise ValueError(
                f"Size mismatch: expected {expected_bytes}, "
                f"received {actual_bytes}"
            )

        # Verify that the reconstructed file is valid JSON.
        try:
            with temporary_output.open(
                "r",
                encoding="utf-8",
            ) as completed_file:
                json.load(completed_file)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            temporary_output.unlink(missing_ok=True)
            raise ValueError(
                "Reconstructed payload is not valid UTF-8 JSON"
            ) from error

        temporary_output.replace(OUTPUT_FILE)

        with transfer_lock:
            transfers.pop(transfer_id, None)

        shutil.rmtree(transfer_directory, ignore_errors=True)

        sha256 = digest.hexdigest()

        print(f"Saved {actual_bytes} bytes to {OUTPUT_FILE}")
        print(f"SHA-256: {sha256}")

        send_json(
            self,
            200,
            {
                "status": "complete",
                "output": str(OUTPUT_FILE),
                "bytes": actual_bytes,
                "sha256": sha256,
            },
        )

    def log_message(self, format_string: str, *args: object) -> None:
        print(
            f"{self.client_address[0]}: "
            f"{format_string % args}"
        )


def main() -> None:
    TEMP_DIRECTORY.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer((HOST, PORT), ReceiverHandler)

    print(f"Listening on http://{HOST}:{PORT}")
    print(f"Completed JSON will be written to {OUTPUT_FILE}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping receiver.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()