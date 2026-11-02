#!/usr/bin/env python3
"""A stand-in for the Go agent that speaks docs/agent-protocol.md.

Every request is appended to <data-dir>/requests.jsonl so tests can see what
the integration sent. The extra method test.emit makes the agent send an
event, so tests can drive pairing and state changes; test.conflict makes it
behave as if the edge replaced its link with another installation's.
"""

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PURPOSES = {"register-home", "home-grant"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def load_key(data_dir: Path) -> ec.EllipticCurvePrivateKey:
    path = data_dir / "home_key.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--lan-listen", default=":4433")
    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    log = data_dir / "requests.jsonl"
    # Each start appends how it was launched, for the tests.
    with (data_dir / "launches.jsonl").open("a") as fh:
        fh.write(
            json.dumps(
                {
                    "otel_disabled": os.environ.get("QUICHARC_OTEL_DISABLED"),
                    "otel_environment": os.environ.get("QUICHARC_OTEL_ENVIRONMENT"),
                }
            )
            + "\n"
        )
    with contextlib.suppress(FileNotFoundError):
        os.unlink(args.socket)
    stop = asyncio.Event()
    config: dict = {}
    # Set while another installation holds the link (test.conflict); like the
    # real agent, only identity.reclaim clears it.
    conflict: dict = {}
    key = load_key(data_dir)
    public = key.public_key()
    point = public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    spki = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        def send(message: dict) -> None:
            writer.write(json.dumps(message).encode() + b"\n")

        def send_state() -> None:
            if conflict:
                data = {
                    "edge": "disconnected",
                    "edge_nodes": [
                        {"node": "edge-a", "connected": False, "rtt_ms": None}
                    ],
                    "identity_conflict": True,
                    "identity_conflict_node": conflict["node"],
                    "identity_conflict_at": conflict["at"],
                }
            else:
                data = {
                    "edge": "connected",
                    "edge_nodes": [
                        {"node": "edge-a", "connected": True, "rtt_ms": 42.5}
                    ],
                }
            data |= {"peers": [], "forwarded_headers_trusted": True, "lan_port": 4433}
            send({"type": "event", "event": "state", "data": data})

        hello = json.loads(await reader.readline())
        if hello.get("protocol", {}).get("min", 99) > 1:
            send(
                {
                    "type": "error",
                    "error": {"code": "unsupported_protocol", "message": "v1 only"},
                }
            )
            await writer.drain()
            writer.close()
            return
        send(
            {"type": "hello", "protocol": 1, "agent": "0.0.0-fake", "capabilities": []}
        )
        send({"type": "event", "event": "state", "data": {"edge": "disconnected"}})
        await writer.drain()
        while line := await reader.readline():
            message = json.loads(line)
            method, params = message.get("method"), message.get("params") or {}
            with log.open("a") as fh:
                fh.write(
                    json.dumps(
                        {
                            "method": method,
                            "params": params,
                            "traceparent": message.get("traceparent"),
                        }
                    )
                    + "\n"
                )
            result: dict = {}
            error = None
            if method == "home_key.get":
                result = {
                    "public_key": b64url(point),
                    "fingerprint": b64url(hashlib.sha256(spki).digest()),
                }
            elif method == "home_key.proof":
                if params.get("purpose") not in PURPOSES:
                    error = {"code": "bad_request", "message": "unknown purpose"}
                else:
                    to_sign = "\n".join(
                        [
                            "quicharc-proof-v1",
                            params["purpose"],
                            params["caller"],
                            params["key_id"],
                            b64url(point),
                            str(params["ts"]),
                        ]
                    ).encode()
                    result = {
                        "proof": b64url(key.sign(to_sign, ec.ECDSA(hashes.SHA256())))
                    }
            elif method == "config.set":
                config.clear()
                config.update(params)
                send_state()
            elif method == "test.conflict":
                conflict.update(node=params["node"], at=params["at"])
                send(
                    {
                        "type": "event",
                        "event": "identity_conflict",
                        "data": {"reason": "identity_in_use", "node": params["node"]},
                    }
                )
                send_state()
            elif method == "identity.reclaim":
                result = {"reclaimed": bool(conflict)}
                conflict.clear()
                send_state()
            elif method == "test.emit":
                send(
                    {
                        "type": "event",
                        "event": params["event"],
                        "data": params.get("data", {}),
                    }
                )
            elif method == "test.crash":
                os._exit(3)
            elif method == "shutdown":
                send(
                    {"type": "response", "id": message["id"], "ok": True, "result": {}}
                )
                await writer.drain()
                stop.set()
                return
            elif method in {
                "status.get",
                "device.approve",
                "device.deny",
                "device.revoke",
                "peer.send_token",
            }:
                pass
            else:
                error = {"code": "unknown_method", "message": method}
            if error:
                send(
                    {
                        "type": "response",
                        "id": message["id"],
                        "ok": False,
                        "error": error,
                    }
                )
            else:
                send(
                    {
                        "type": "response",
                        "id": message["id"],
                        "ok": True,
                        "result": result,
                    }
                )
            await writer.drain()

    server = await asyncio.start_unix_server(handle, path=args.socket)
    os.chmod(args.socket, 0o600)
    async with server:
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
