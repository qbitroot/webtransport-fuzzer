#!/usr/bin/env python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
An example WebTransport over HTTP/3 echo server based on the aioquic library.

Instrumented with WTFUZZ| structured log lines for the webtransport-fuzzer.
"""

import argparse
import asyncio
import logging
import sys
from collections import defaultdict
from typing import Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
    DatagramReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import stream_is_unidirectional
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    StreamReset,
    QuicEvent,
)

BIND_ADDRESS = "0.0.0.0"
BIND_PORT = 6000

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WTFUZZ structured logging
# ---------------------------------------------------------------------------
# Format: WTFUZZ|<conn_idx>|EVENT|key=val|key=val
#
# Generic events (language-agnostic, derived from the WT spec):
#   SESSION_OPEN      - WebTransport session established
#   SESSION_CLOSE     - WebTransport session terminated
#   RECV_BIDI         - Data received on bidirectional stream
#   RECV_UNI          - Data received on unidirectional stream
#   RECV_DATAGRAM     - Datagram received
#   ECHO              - Echo response sent
#   STREAM_RESET      - Stream reset received
# ---------------------------------------------------------------------------


def wtfuzz(conn_idx: int, event: str, **kv):
    """Print a WTFUZZ structured log line to stdout (flushed immediately)."""
    parts = [f"WTFUZZ|{conn_idx}|{event}"]
    for k, v in kv.items():
        parts.append(f"{k}={v}")
    print("|".join(parts), flush=True)


# Global connection counter for aioquic
_connection_counter = 0


class EchoHandler:
    """
    Echo protocol handler.
    - Bidirectional streams: echo back data on the same stream once closed.
    - Unidirectional streams: echo back on a new unidirectional stream.
    - Datagrams: echo back immediately.
    """

    def __init__(self, conn_idx, session_id, http: H3Connection) -> None:
        self._conn_idx = conn_idx
        self._session_id = session_id
        self._http = http
        self._payloads = defaultdict(bytearray)

    def h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, DatagramReceived):
            wtfuzz(self._conn_idx, "RECV_DATAGRAM", session_id=self._session_id)
            self._http.send_datagram(self._session_id, event.data)
            wtfuzz(self._conn_idx, "ECHO", type="datagram", session_id=self._session_id)

        if isinstance(event, WebTransportStreamDataReceived):
            self._payloads[event.stream_id] += event.data

            if stream_is_unidirectional(event.stream_id):
                wtfuzz(self._conn_idx, "RECV_UNI", stream_id=event.stream_id)
            else:
                wtfuzz(self._conn_idx, "RECV_BIDI", stream_id=event.stream_id)

            if event.stream_ended:
                if stream_is_unidirectional(event.stream_id):
                    response_id = self._http.create_webtransport_stream(
                        self._session_id, is_unidirectional=True
                    )
                else:
                    response_id = event.stream_id
                payload = self._payloads[event.stream_id]
                self._http._quic.send_stream_data(response_id, payload, end_stream=True)
                stream_type = (
                    "uni" if stream_is_unidirectional(event.stream_id) else "bidi"
                )
                wtfuzz(self._conn_idx, "ECHO", type=stream_type, stream_id=response_id)
                self.stream_closed(event.stream_id)

    def stream_closed(self, stream_id: int) -> None:
        try:
            del self._payloads[stream_id]
        except KeyError:
            pass


class WebTransportProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._handler: Optional[EchoHandler] = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic, enable_webtransport=True)
        elif isinstance(event, StreamReset) and self._handler is not None:
            wtfuzz(
                self._handler._conn_idx,
                "STREAM_RESET",
                stream_id=event.stream_id,
                error_code=event.error_code,
            )
            self._handler.stream_closed(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            if self._handler:
                wtfuzz(
                    self._handler._conn_idx,
                    "SESSION_CLOSE",
                    session_id=self._handler._session_id,
                )
                self._handler = None

        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            headers = {}
            for header, value in event.headers:
                headers[header] = value
            if (
                headers.get(b":method") == b"CONNECT"
                and headers.get(b":protocol") == b"webtransport"
            ):
                self._handshake_webtransport(event.stream_id, headers)
            else:
                self._send_response(event.stream_id, 400, end_stream=True)

        if self._handler:
            self._handler.h3_event_received(event)

    def _handshake_webtransport(
        self, stream_id: int, request_headers: Dict[bytes, bytes]
    ) -> None:
        authority = request_headers.get(b":authority")
        path = request_headers.get(b":path")
        if authority is None or path is None:
            self._send_response(stream_id, 400, end_stream=True)
            return
        if path == b"/echo":
            assert self._handler is None
            global _connection_counter
            current_conn_idx = _connection_counter
            _connection_counter += 1
            self._handler = EchoHandler(current_conn_idx, stream_id, self._http)
            self._send_response(stream_id, 200)
            wtfuzz(current_conn_idx, "SESSION_OPEN", session_id=stream_id)
        else:
            self._send_response(stream_id, 404, end_stream=True)

    def _send_response(
        self, stream_id: int, status_code: int, end_stream=False
    ) -> None:
        headers = [(b":status", str(status_code).encode())]
        self._http.send_headers(
            stream_id=stream_id, headers=headers, end_stream=end_stream
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args()

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(args.certificate, args.key)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        serve(
            BIND_ADDRESS,
            BIND_PORT,
            configuration=configuration,
            create_protocol=WebTransportProtocol,
        )
    )
    try:
        wtfuzz(0, "SERVER_READY", bind=f"{BIND_ADDRESS}:{BIND_PORT}")
        loop.run_forever()
    except KeyboardInterrupt:
        pass
