# WebTransport over HTTP/3 Protocol Specification

> Reference: **IETF draft-ietf-webtrans-http3-14** (expires 23 April 2026)  
> W3C: **WD-webtransport-20251217** (17 December 2025)

---

## 1. Protocol Stack

```
┌─────────────────────────────────────┐
│           Application               │
├─────────────────────────────────────┤
│     WebTransport Session API        │
├──────────┬───────────┬──────────────┤
│ Streams  │ Datagrams │   Capsules   │
├──────────┴───────────┴──────────────┤
│              HTTP/3                 │
├─────────────────────────────────────┤
│            QUIC (RFC 9000)          │
├─────────────────────────────────────┤
│              UDP                    │
└─────────────────────────────────────┘
```

WebTransport over HTTP/3 runs on QUIC, using HTTP/3 framing for session management and native QUIC streams for data transfer.

---

## 2. Session Establishment

### CONNECT Request Headers

```http
:method = CONNECT
:scheme = https
:authority = example.com:443
:path = /webtransport
:protocol = webtransport
```

### Server Response (Success)

```http
:status = 200
```

The **CONNECT stream** becomes the session control channel. Its stream ID is the **Session ID** used to identify all associated streams and datagrams.

### Session ID Encoding

Session IDs are encoded as **QUIC Variable-Length Integers**:

| Range | Encoding | Bytes |
|-------|----------|-------|
| 0-63 | `0xxxxxxx` | 1 |
| 64-16383 | `01xxxxxx xxxxxxxx` | 2 |
| 16384-1073741823 | `10xxxxxx ...` | 4 |
| Larger | `11xxxxxx ...` | 8 |

---

## 3. WebTransport Features

### 3.1 Unidirectional Streams

Client creates stream with type byte: `0x54`

```
Stream Header:
┌────────────────┬────────────────┬─────────────┐
│ Stream Type    │ Session ID     │ Data...     │
│ (VarInt 0x54)  │ (VarInt)       │             │
└────────────────┴────────────────┴─────────────┘
```

### 3.2 Bidirectional Streams

Client creates via HTTP/3 mechanism. Server can also create bidirectional streams with type: `0x41`

```
Stream Header (server-initiated):
┌────────────────┬────────────────┬─────────────┐
│ Type (0x41)    │ Session ID     │ Data...     │
└────────────────┴────────────────┴─────────────┘
```

### 3.3 Datagrams

Sent via QUIC DATAGRAM frames (RFC 9221). Quarter-stream ID encodes target session.

```
DATAGRAM Payload:
┌────────────────────┬─────────────┐
│ Quarter Stream ID  │ Data...     │
│ (VarInt)           │             │
└────────────────────┴─────────────┘
```

---

## 4. Capsule Types (HTTP Capsule Protocol - RFC 9297)

Capsules are sent on the CONNECT stream for session control.

### Format

```
┌────────────────┬────────────────┬─────────────┐
│ Type (VarInt)  │ Length (VarInt)│ Payload     │
└────────────────┴────────────────┴─────────────┘
```

### 4.1 Session Management Capsules

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x2843` | **WT_CLOSE_SESSION** | Terminate session with error code |
| `0x78ae` | **WT_DRAIN_SESSION** | Initiate graceful shutdown |
| `0x190B4D38` | **PADDING** | No semantic value, padding |

#### WT_CLOSE_SESSION (`0x2843`)

```
┌────────────────┬────────────────┬────────────────────┬───────────────────────────┐
│ Type: 0x2843   │ Length (VarInt)│ Error Code (32-bit)│ Message (UTF-8, ≤1024 B)  │
│ (2 bytes:      │                │                    │                           │
│  0x68 0x43)    │                │                    │                           │
└────────────────┴────────────────┴────────────────────┴───────────────────────────┘
```

VarInt encoding for `0x2843`: `0x68 0x43` (2-byte form: `0x40 | (10307 >> 8)` = `0x68`, low byte = `0x43`)

#### WT_DRAIN_SESSION (`0x78ae`)

```
┌────────────────────┬──────────────┐
│ Type: 0x78ae       │ Length: 0x00 │
│ (4-byte VarInt:    │              │
│  0x80004F5E or     │              │
│  see encoding)     │              │
└────────────────────┴──────────────┘
```

**Note:** `0x78ae` = 30894, fits in 2-byte VarInt: `0x40 | (30894 >> 8)` = `0xF8`, but 30894 > 16383, so requires 4-byte encoding.

### 4.2 Stream Control Capsules (used in HTTP/2 fallback)

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x190B4D3B..3C` | **WT_STREAM** | Stream data (LSB=FIN) |
| `0x190B4D39` | **WT_RESET_STREAM** | Abort stream sending |
| `0x190B4D3A` | **WT_STOP_SENDING** | Request peer stop sending |

### 4.3 Flow Control Capsules

| Type Code | Name | Description |
|-----------|------|-------------|
| `0x190B4D3D` | **WT_MAX_DATA** | Session data limit |
| `0x190B4D3E` | **WT_MAX_STREAM_DATA** | Per-stream data limit |
| `0x190B4D3F` | **WT_MAX_STREAMS (BIDI)** | Bidirectional stream limit |
| `0x190B4D40` | **WT_MAX_STREAMS (UNI)** | Unidirectional stream limit |
| `0x190B4D41` | **WT_DATA_BLOCKED** | Session flow blocked |
| `0x190B4D42` | **WT_STREAM_DATA_BLOCKED** | Stream flow blocked |
| `0x190B4D43` | **WT_STREAMS_BLOCKED (BIDI)** | Bidi stream limit hit |
| `0x190B4D44` | **WT_STREAMS_BLOCKED (UNI)** | Uni stream limit hit |

---

## 5. State Machines

### 5.1 Session States

```
[Connecting] ──success──▶ [Established] ──drain──▶ [Draining] ──▶ [Terminated]
      │                        │                                       ▲
      │                        └────close/error────────────────────────┘
      └──failure──▶ [Failed]
```

### 5.2 Stream States (Sender)

```
[Ready] ── open ──▶ [Send] ── FIN ──▶ [DataSent] ── ACK ──▶ [DataRecvd] ──▶ (done)
                       │                  │
                       └── RESET ─────────┴──▶ [ResetSent] ── ACK ──▶ [ResetRecvd]
```

### 5.3 Stream States (Receiver)

```
[Recv] ── FIN ──▶ [SizeKnown] ── all data ──▶ [DataRecvd] ── consumed ──▶ [DataRead]
   │                  │
   └── RESET ─────────┴──▶ [ResetRecvd] ── notified ──▶ [ResetRead]
```

---

## 6. Error Codes

### HTTP/3 Error Codes

| Code | Name | Meaning |
|------|------|---------|
| `0x0100-0x01ff` | `H3_*` | HTTP/3 errors |
| `0x?` | `H3_ID_ERROR` | Invalid session ID |
| `0x?` | `WT_SESSION_GONE` | Session terminated |

### Application Error Codes

| Value | Meaning |
|-------|---------|
| `0` | No error (clean close) |
| Other | Application-defined |

---

## 7. Key Protocol Invariants

1. **Session ID must be client-initiated bidirectional stream ID**
2. **WT_MAX_STREAMS is cumulative** (not delta)
3. **WT_STREAM data cannot be sent after FIN or RESET**
4. **WT_CLOSE_SESSION must be followed by FIN on CONNECT stream**
5. **Empty WT_STREAM capsules invalid unless opening/closing stream**
6. **Reliable Size in WT_RESET_STREAM must ≥ bytes already received**

---

## 8. Fuzzing Target Areas

### High-Priority Targets

1. **VarInt parsing** - Overflow, max values, truncation
2. **Session ID validation** - Wrong stream type, reuse, cross-session
3. **State machine violations** - Post-FIN data, duplicate RESETs
4. **Flow control** - Exceed limits, negative values, decreasing MAX_*
5. **Capsule framing** - Length mismatches, unknown types

### Multi-Step Sequences

1. Open stream → Close → Send more data
2. Send MAX_STREAMS=10 → Open 10 → Send MAX_STREAMS=5
3. WT_DRAIN_SESSION → Open new stream
4. WT_CLOSE_SESSION → Continue sending
 
### DoS Testing
 
**Stream Exhaustion (`wt_stream_dos`)**:
- Attempts to open 10,000 unidirectional streams in a single burst.
- **Goal**: Verify `max_streams` limit enforcement (server should reject or close connection).
- **Payload**: Minimal valid stream frames to maximize throughput and hit limits quickly.
