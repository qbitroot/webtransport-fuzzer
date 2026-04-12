# webtransport-fuzzer

Boofuzz-based fuzzer for the [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) protocol.

Targets the capsule layer on the CONNECT stream and data transports (bidirectional streams, unidirectional streams, datagrams). Tested against local server implementations in the `server/` directory:

- **`server/aioquic`** — Python echo server using [aioquic](https://github.com/aiortc/aioquic) (draft-03 / GEN1)
- **`server/wtransport`** — Rust echo server using [wtransport](https://github.com/BiagioFesta/wtransport) (draft-09 / GEN3)
- **`server/webtransport-go`** — Go echo server using [webtransport-go](https://github.com/quic-go/webtransport-go) (HTTP/3 over QUIC, self-signed TLS, listens on `0.0.0.0:6161`)

---

## Quick start

```bash
# Validate connection
uv run python main.py --no-fuzz --url https://127.0.0.1:6161/echo

# One-shot capsule fuzzer (single malformed capsule per connection)
uv run python main.py --mode oneshot --url https://127.0.0.1:6161/echo

# Multistep scenario fuzzer (interleaved data + capsule sequences)
uv run python main.py --mode multistep --url https://127.0.0.1:6161/echo

# Scenario-lastfuzz (scenarios in order, last step fuzzed like oneshot)
uv run python main.py --mode scenario-lastfuzz --url https://127.0.0.1:6161/echo

# All modes combined in a single run
uv run python main.py --mode all --url https://127.0.0.1:6161/echo

# With server subprocess management
uv run python main.py --mode multistep --url https://127.0.0.1:6161/echo \
    --server-cmd "uv run server/aioquic/server.py cert.pem key.pem 2>&1 | tee server.log"

# Resume from a specific test case index
uv run python main.py --mode multistep --start-index 42 --end-index 100

# boofuzz web UI available at http://localhost:26000 during a run
```

---

## Fuzzing modes

### `--mode oneshot`

Sends a single malformed capsule per connection on the CONNECT stream (the WebTransport session control channel). The capsule type, length field, and payload are all independently fuzzed using interesting boundary values, overlong VarInt encodings, cross-layer type confusion (injecting QUIC/HTTP3 frame type bytes as capsule types), and more.

Each test case is one `[CapsuleType][CapsuleLength][Payload]` blob. After sending, the health check (echo probe on a fresh bidirectional stream) verifies the server is still alive.

### `--mode scenario-lastfuzz`

Executes each scenario in its original step order (no permutations or mutations), but replaces the **last step** with a fuzzed malformed capsule — the same `[CapsuleType][CapsuleLength][Payload]` values used by oneshot mode.

This combines the state-richness of multistep scenarios (the server has real streams and data in flight) with oneshot-style capsule coverage. Each test case plays the scenario's prefix steps as legitimate traffic to put the server into a specific state, then fires a single malformed capsule.

Test cases = scenarios × oneshot fuzz values. Uses the same 12 scenarios as multistep and the same `ALL_INTERESTING_BYTES` pool as oneshot.

### `--mode all`

Runs all three modes (oneshot, multistep, scenario-lastfuzz) in a single unified session. Oneshot capsules are wrapped as single-step scenarios so the entire run uses the same executor. Test cases are deduplicated across modes.

This is the "fire and forget" option for maximum coverage in one invocation.

### `--mode multistep`

Executes multi-step scenarios that interleave real data activity with capsule sequences on a single live session. Designed to trigger state-machine bugs: use-after-free, state confusion after close, crash-on-reorder, etc.

Each **scenario** is a list of steps, where each step is one of:

| Step            | What happens                                                                                              |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| `bidi(hex)`     | Opens a bidirectional WebTransport stream, sends payload, awaits echo (1 s timeout; timeout is non-fatal) |
| `uni(hex)`      | Opens a unidirectional stream, sends payload, no echo expected                                            |
| `datagram(hex)` | Sends a QUIC datagram                                                                                     |
| `capsule(hex)`  | Sends a raw WebTransport capsule on the CONNECT stream                                                    |
| `sleep(Xs)`     | Pause between steps                                                                                       |

The **mutator** generates all interesting variants from each scenario:

- All permutations (reordering)
- Each step duplicated in place and at end
- Each step omitted
- Rapid-fire: same step repeated 2×, 5×, 10×
- Reversed order
- Prohibited capsule injection at every position (`WT_MAX_STREAM_DATA` / `WT_STREAM_DATA_BLOCKED`, which MUST cause a session error per draft-15 §5.4)
- Post-CLOSE activity: bidi/uni/datagram/capsule sent after a CLOSE_SESSION

**~920 unique test cases across 12 scenarios.**

#### Scenarios

| Scenario                         | Steps                                     | Tests                                   |
| -------------------------------- | ----------------------------------------- | --------------------------------------- |
| `bidi_then_shutdown`             | bidi → drain → close                      | Close race with active echo             |
| `all_transports_then_close`      | bidi + uni + dgram → close                | All 3 paths, then teardown              |
| `capsule_between_bidi`           | bidi → MAX_DATA → bidi                    | Capsule disrupts stream processing      |
| `drain_mid_data`                 | bidi → drain → bidi + uni                 | Drain while streams are active          |
| `flow_with_streams`              | MAX_STREAMS → bidi → MAX_DATA → uni       | Flow control with live data             |
| `close_error_after_data`         | bidi + dgram → close(42, msg)             | Error code parsing after real activity  |
| `rapid_bidi_close`               | bidi × 3 → close                          | Rapid stream creation before close      |
| `datagram_flood_drain`           | dgram × 3 → drain                         | Drain during datagram processing        |
| `uni_capsule_interleave`         | uni/capsule alternating × 5               | Capsules don't corrupt uni handling     |
| `kitchen_sink`                   | all 6 action types                        | Maximum permutation surface             |
| `contradictory_limits_with_data` | MAX_DATA(0) → bidi → MAX_DATA(64K) → bidi | Limit changes with live data            |
| `blocked_then_create`            | STREAMS_BLOCKED → bidi → BLOCKED → uni    | Creating streams despite blocked signal |

#### Version compatibility

All three server generations (GEN1 draft-03, GEN3 draft-09, GEN4 draft-15) are targeted simultaneously. Unknown capsule types MUST be silently ignored per RFC 9297, so flow-control capsules sent to GEN1 servers are valid test cases — if a GEN1 server crashes on them, that's a bug.

---

## Server fingerprinting

Before fuzzing, use `get-server-version.py` to identify which draft generation the target implements:

```bash
uv run get-server-version.py --no-verify 127.0.0.1 6161
```

---

## Logging

### SQLite log database

All test cases are recorded to a SQLite database (`boofuzz-results/run_<timestamp>.db`). Specify a path with `--db`.

Schema:

```
test_cases
  id              INTEGER PRIMARY KEY
  test_index      INTEGER              -- boofuzz mutant index
  sent_data       TEXT                 -- newline-separated steps (see below)
  is_healthcheck  INTEGER              -- 1 for post-test echo probes
  log_group_id    INTEGER FK           -- references log_groups(id)
  timestamp       REAL

log_groups
  id              INTEGER PRIMARY KEY
  fingerprint     TEXT UNIQUE          -- SHA-256 of joined server output lines
  raw_text        TEXT                 -- full server output for this group
```

**`sent_data` format** — one line per step, each in `action(hex-payload)` form:

```
bidi(48454c4c4f)
capsule(800078ae00)
capsule(68430400000000)
uni(554e49)
datagram(4447)
```

For oneshot mode a single line `capsule(hex)` is stored.

**Deduplication**: server output is SHA-256 fingerprinted. Multiple test cases that produce identical server output share one `log_group` row, making it easy to group by failure mode.

### WTFUZZ structured server log format

Instrumented servers emit structured lines to **stdout**:

```
WTFUZZ|<conn_idx>|EVENT|key1=val1|key2=val2|...
```

After a fuzzing run, correlate test cases with server output offline:

```bash
uv run analyze_logs.py --log server.log --db boofuzz-results/run_<timestamp>.db
```

#### Event catalog

| Event           | Key-value pairs                                         | Description                            |
| --------------- | ------------------------------------------------------- | -------------------------------------- |
| `SERVER_READY`  | `bind=host:port`                                        | Server is listening                    |
| `SESSION_OPEN`  | `session_id=<id>`                                       | WebTransport session established       |
| `SESSION_CLOSE` | `session_id=<id>`                                       | Session terminated                     |
| `RECV_BIDI`     | `stream_id=<id>`                                        | Data received on bidirectional stream  |
| `RECV_UNI`      | `stream_id=<id>`                                        | Data received on unidirectional stream |
| `RECV_DATAGRAM` | `session_id=<id>`                                       | Datagram received                      |
| `ECHO`          | `type=bidi\|uni\|datagram`, `session_id` or `stream_id` | Echo response sent                     |
| `STREAM_RESET`  | `stream_id=<id>`, `error_code=<code>`                   | Stream reset received                  |

Standard logging (warnings, stack traces) goes to **stderr** and is not captured by the pipeline. Any server line not starting with `WTFUZZ|` is flagged as `[SERVER RAW]` — these typically indicate panics or assertion failures.

> **Note (webtransport-go):** The `webtransport-go` library does not expose the underlying QUIC stream ID through its API, so `RECV_BIDI`, `RECV_UNI`, and `ECHO` events from `server/webtransport-go` omit the `stream_id` field. This is a library limitation and does not affect fuzzing coverage.

### Adding a new server

1. Maintain a global connection counter (starting at 0).
2. Print `WTFUZZ|<conn_idx>|EVENT|key=val|...` to **stdout**, flushed immediately.
3. Use **stderr** for all other logging.
4. Implement an echo server: echo back whatever arrives on bidi streams, uni streams, and datagrams.

---

## Architecture

```
main.py                 — CLI entry point, boofuzz Session setup
src/
  boofuzz_definitions.py  — oneshot capsule definitions; multistep scenarios
  sequence_mutator.py     — step type helpers; mutation engine (permute/dup/omit/inject)
  fuzzer_connection.py    — boofuzz ITargetConnection; executes step scenarios
  webtransport_client.py  — aioquic WebTransport client (bidi/uni/datagram/capsule)
  echo_monitor.py         — post-test health check via echo probe
  request_logger.py       — boofuzz monitor that writes test cases to SQLite
  log_db.py               — SQLite schema and access
  server_manager.py       — optional server subprocess lifecycle
analyze_logs.py           — offline log correlation tool
get-server-version.py     — server draft-version fingerprinting tool
server/
  aioquic/                — Python echo server (draft-03)
  wtransport/             — Rust echo server (draft-09)
  webtransport-go/        — Go echo server (webtransport-go / HTTP3+QUIC)
```

---

## Notes

- Use `uv run` for all commands (manages the venv).
- TLS verification is disabled by default (self-signed certs). Use `--no-verify` with `get-server-version.py`.
- To test from a browser: install mkcert and launch Chrome with `--origin-to-force-quic-on=127.0.0.1:6161`. Chrome does not support [localhost TLS for HTTP/3](https://news.ycombinator.com/item?id=41748640).
- The boofuzz web UI is available at `http://localhost:26000` during a run.
