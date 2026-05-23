#!/usr/bin/env python3
"""WebTransport draft version probe tool.

Usage:
    uv run server_version.py <host> <port> [--path /echo] [--cert ca.pem] [--no-verify]
"""

import argparse
import asyncio
import ssl
from typing import Optional

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, ProtocolNegotiated, ConnectionTerminated

S_ENABLE_WT_GEN1 = 0x2B603742
S_MAX_SESSIONS_GEN2A = 0x2B603743
S_MAX_SESSIONS_GEN2B = 0xC671706A
S_WT_ENABLED_GEN4 = 0x2C7CF000
S_ENABLE_CONNECT = 0x08
S_H3_DATAGRAM = 0x33

SETTING_LABELS = {
    S_ENABLE_WT_GEN1: "ENABLE_WEBTRANSPORT       (draft-02/03, GEN1)",
    S_MAX_SESSIONS_GEN2A: "WEBTRANSPORT_MAX_SESSIONS (draft-04,    GEN2A)",
    S_MAX_SESSIONS_GEN2B: "WEBTRANSPORT_MAX_SESSIONS (draft-07+,   GEN2B/3)",
    S_WT_ENABLED_GEN4: "WT_ENABLED                (draft-15,    GEN4)",
    S_ENABLE_CONNECT: "ENABLE_CONNECT_PROTOCOL",
    S_H3_DATAGRAM: "H3_DATAGRAM",
}

GENERATIONS = [
    ("GEN1", "draft-02/03  - ENABLE_WEBTRANSPORT, 8-bit errors, Sec header"),
    ("GEN2A", "draft-04/06  - both ENABLE_WEBTRANSPORT + MAX_SESSIONS, 8-bit errors"),
    (
        "GEN2B",
        "draft-07/08  - MAX_SESSIONS=0xc671706a, 32-bit errors, no RESET_STREAM_AT",
    ),
    ("GEN3", "draft-09/11  - same key, RESET_STREAM_AT added"),
    ("GEN4", "draft-15     - WT_ENABLED=0x2c7cf000, webtransport-h3 token"),
]


class ProbeProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self.server_settings: dict[int, int] = {}
        self.connect_responses: dict[str, dict] = {}
        self._pending: dict[int, str] = {}
        self._done = asyncio.Event()
        self._probes_sent = 0
        self._probes_done = 0

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic, enable_webtransport=True)
        if isinstance(event, ConnectionTerminated):
            self._done.set()
        if self._http is not None:
            for h3_event in self._http.handle_event(event):
                self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        if not isinstance(event, HeadersReceived):
            return
        token = self._pending.get(event.stream_id)
        if token is None:
            return
        headers = {k: v for k, v in event.headers}
        status = int(headers.get(b":status", b"0"))
        sec = headers.get(b"sec-webtransport-http3-draft")
        self.connect_responses[token] = {
            "status": status,
            "sec_draft_header": sec.decode() if sec else None,
            "raw_headers": {
                k.decode(errors="replace"): v.decode(errors="replace")
                for k, v in event.headers
            },
        }
        self._probes_done += 1
        if self._probes_done >= self._probes_sent:
            self._done.set()

    def send_connect(self, authority: str, path: str, token: str) -> None:
        assert self._http is not None
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._pending[stream_id] = token
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b":protocol", token.encode()),
                (b"sec-webtransport-http3-draft02", b"1"),
            ],
        )
        self._probes_sent += 1

    def gather_settings(self) -> None:
        if self._http is not None and self._http.received_settings:
            self.server_settings = dict(self._http.received_settings)

    async def wait_done(self, timeout: float = 5.0) -> None:
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass


def classify(
    settings: dict[int, int], responses: dict[str, dict]
) -> tuple[str, list[str]]:
    old_resp = responses.get("webtransport")
    new_resp = responses.get("webtransport-h3")
    old_ok = old_resp is not None and 200 <= old_resp["status"] < 300
    new_ok = new_resp is not None and 200 <= new_resp["status"] < 300

    has1 = S_ENABLE_WT_GEN1 in settings
    has2a = S_MAX_SESSIONS_GEN2A in settings
    has2b = S_MAX_SESSIONS_GEN2B in settings
    has4 = S_WT_ENABLED_GEN4 in settings

    if has4 or new_ok:
        ev = []
        if has4:
            ev.append(
                f"SETTINGS key 0x{S_WT_ENABLED_GEN4:08x} (draft-15 SETTINGS_WT_ENABLED)"
            )
        if new_ok:
            ev.append(":protocol=webtransport-h3 accepted")
        return "GEN4", ev

    if has1 and has2a:
        ev = [
            f"SETTINGS 0x{S_ENABLE_WT_GEN1:08x} (ENABLE_WEBTRANSPORT) present",
            f"SETTINGS 0x{S_MAX_SESSIONS_GEN2A:08x} (MAX_SESSIONS draft-04 key) also present",
        ]
        if old_ok:
            ev.append(":protocol=webtransport accepted")
        return "GEN2A", ev

    if has1 and not has2a and not has2b:
        ev = [
            f"SETTINGS key 0x{S_ENABLE_WT_GEN1:08x} (draft-02/03 ENABLE_WEBTRANSPORT)"
        ]
        if old_ok:
            ev.append(":protocol=webtransport accepted")
        if old_resp and old_resp.get("sec_draft_header"):
            ev.append(
                f"Sec-Webtransport-Http3-Draft: {old_resp['sec_draft_header']} in response"
            )
        return "GEN1", ev

    if has2b:
        ev = [
            f"SETTINGS key 0x{S_MAX_SESSIONS_GEN2B:08x} (WEBTRANSPORT_MAX_SESSIONS, draft-07..11)",
            f"  MAX_SESSIONS value = {settings[S_MAX_SESSIONS_GEN2B]}",
        ]
        if old_ok:
            ev.append(":protocol=webtransport accepted")
        ev += [
            "Cannot distinguish draft-07/08 (GEN2B) from draft-09/11 (GEN3) from H3 SETTINGS alone",
            "  -> Both use 0xc671706a; draft-11+ added RESET_STREAM_AT (QUIC transport param, not in H3 SETTINGS)",
        ]
        return "GEN3", ev

    return "UNKNOWN", ["No recognised WebTransport SETTINGS key found"]


async def probe(
    host: str, port: int, path: str, cafile: Optional[str], no_verify: bool
) -> None:
    config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        max_datagram_frame_size=65536,
        verify_mode=ssl.CERT_NONE if no_verify else ssl.CERT_REQUIRED,
    )
    if cafile:
        config.load_verify_locations(cafile)

    authority = f"{host}:{port}"
    print(f"[*] Probing {authority}{path} ...")

    async with connect(
        host,
        port,
        configuration=config,
        create_protocol=ProbeProtocol,
        wait_connected=True,
    ) as _proto:
        proto: ProbeProtocol = _proto  # type: ignore[assignment]
        await asyncio.sleep(0.3)
        proto.gather_settings()
        proto.send_connect(authority, path, "webtransport")
        proto.send_connect(authority, path, "webtransport-h3")
        proto._quic.send_ping(0)
        proto.transmit()
        await proto.wait_done(timeout=6.0)

    settings, responses = proto.server_settings, proto.connect_responses

    print("\nSettings:")
    if not settings:
        print("  (none received)")
    else:
        for k, v in sorted(settings.items()):
            print(f"  0x{k:08x} = {v:<6}  {SETTING_LABELS.get(k, '')}")

    print("\nCONNECT probes:")
    for token in ("webtransport", "webtransport-h3"):
        resp = responses.get(token)
        if resp is None:
            print(f"  {token}: no response")
        else:
            status = resp["status"]
            sec = resp.get("sec_draft_header")
            tag = f"  [Sec-Webtransport-Http3-Draft: {sec}]" if sec else ""
            word = "ACCEPTED" if 200 <= status < 300 else f"REJECTED ({status})"
            print(f"  {token}: {word}{tag}")

    gen, evidence = classify(settings, responses)

    print("\nResult:")
    for label, desc in GENERATIONS:
        print(f"  {'*' if label == gen else ' '} {label}  {desc}")
    print(f"\n  Evidence:")
    for e in evidence:
        print(f"    - {e}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe a WebTransport/HTTP3 server - detect draft generation"
    )
    parser.add_argument("host", help="Server hostname or IP")
    parser.add_argument("port", type=int, help="UDP port")
    parser.add_argument(
        "--path", default="/echo", help="WebTransport path (default: /echo)"
    )
    parser.add_argument(
        "--cert",
        dest="cafile",
        default=None,
        help="CA certificate file for TLS verification",
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Skip TLS certificate verification"
    )
    args = parser.parse_args()
    asyncio.run(
        probe(
            host=args.host,
            port=args.port,
            path=args.path,
            cafile=args.cafile,
            no_verify=args.no_verify,
        )
    )


if __name__ == "__main__":
    main()
