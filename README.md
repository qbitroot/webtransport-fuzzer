# webtransport-fuzzer

Boofuzz-based WebTransport protocol fuzzer.

Tested against a local server (see server directory), based on [w3c/webtransport ipv4_echo_server.py](https://github.com/w3c/webtransport/blob/main/samples/echo/py-server/ipv4_echo_server.py).

## Current progress

[![asciicast](https://asciinema.org/a/WYtY0LEHRUk9pH29YYNTZSugk.svg)](https://asciinema.org/a/WYtY0LEHRUk9pH29YYNTZSugk)

---

## Logging Standard

The fuzzer uses a two-layer logging system: **structured WTFUZZ lines** emitted by the server, and a **SQLite log database** that stores them verbatim and correlates them with fuzzer test cases.

### WTFUZZ Structured Log Format

All instrumented servers must emit structured log lines to **stdout** in this pipe-delimited format:

```
WTFUZZ|EVENT|key1=val1|key2=val2|...
```

- **Prefix**: Every structured line starts with `WTFUZZ|` (defined as `WTFUZZ_PREFIX` in `src/log_db.py:26`).
- **EVENT**: A short, uppercase event name (see table below).
- **Key-value pairs**: Zero or more `key=value` segments, separated by `|`.
- **Flush**: Lines must be flushed immediately (`flush=True`) so the monitor can read them without delay.

Standard Python logging (warnings, debug, etc.) goes to **stderr** and is not captured by the fuzzer pipeline.

#### Event Catalog

| Event            | Key-value pairs                  | Description                              |
|------------------|----------------------------------|------------------------------------------|
| `SERVER_READY`   | `bind=<host>:<port>`             | Server is listening and ready             |
| `SESSION_OPEN`   | `session_id=<id>`                | WebTransport session established          |
| `SESSION_CLOSE`  | `session_id=<id>`                | WebTransport session terminated           |
| `RECV_BIDI`      | `stream_id=<id>`                 | Data received on a bidirectional stream   |
| `RECV_UNI`       | `stream_id=<id>`                 | Data received on a unidirectional stream  |
| `RECV_DATAGRAM`  | `session_id=<id>`                | Datagram received                         |
| `ECHO`           | `type=<bidi\|uni\|datagram>`, `session_id=<id>` or `stream_id=<id>` | Echo response sent |
| `STREAM_RESET`   | `stream_id=<id>`, `error_code=<code>` | Stream reset received                |

These events are language-agnostic and derived from the WebTransport spec, so any server implementation (not just the Python echo server) can emit them.

### Log Database (SQLite)

`LogDB` (`src/log_db.py`) stores all captured output in a normalized SQLite database with WAL mode enabled.

Server output is **stored verbatim** — no parsing or validation is performed. Because the WTFUZZ format is already structured and self-describing, the raw lines *are* the structured data. This also means that if the server emits unexpected output (panics, stack traces, assertion failures), it is captured alongside the structured lines, making anomalies immediately visible by their deviation from the normal pattern.

#### Schema

```
log_groups
  id            INTEGER PRIMARY KEY
  fingerprint   TEXT UNIQUE          -- SHA-256 of the joined raw lines
  raw_text      TEXT                 -- full server output for this group (stored as-is)

test_cases
  id            INTEGER PRIMARY KEY
  test_index    INTEGER              -- boofuzz mutant index
  sent_data     BLOB                 -- the fuzzed payload that was sent
  log_group_id  INTEGER FK           -- references log_groups(id)
  timestamp     REAL                 -- epoch time of recording
```

**Deduplication**: Server output is fingerprinted (SHA-256 of the concatenated lines). If multiple test cases produce identical server output, they all reference the same `log_group` row. This makes it trivial to group test cases by failure mode.

### Server Log Monitor

`ServerLogMonitor` (`src/server_log_monitor.py`) is a boofuzz `BaseMonitor` that bridges the server process and the log database:

1. **`pre_send`** — Drains any buffered server output between test cases (e.g. health-check noise).
2. **`post_send`** — Drains all server output since last drain, calls `LogDB.record_test_case()` to store it, and logs a summary (`N structured + M raw lines`) to boofuzz's logger.
3. **Raw line flagging** — Any line that does *not* start with `WTFUZZ|` is logged prominently as `[SERVER RAW]` since these typically indicate panics, exceptions, or unexpected output.
4. **Liveness check** — Returns `False` (triggering boofuzz failure) if the server process has died.

### Adding a New Server Implementation

To instrument a new server for this fuzzer:

1. Print `WTFUZZ|EVENT|key=val|...` lines to **stdout**, flushed immediately.
2. Send all other logging to **stderr**.
3. Use the event names from the catalog above for consistency across implementations.

---

Note for server: if you want to test the server locally from the browser, after installing mkcert, run chrome with `--origin-to-force-quic-on=127.0.0.1:6161` - Chrome does not support [localhost TLS certificates for HTTP/3](https://news.ycombinator.com/item?id=41748640).
