# webtransport-fuzzer

## Setup

**Requirements:** Python ≥ 3.11, [`uv`](https://github.com/astral-sh/uv), Rust toolchain (for wtransport), Go ≥ 1.21 (for webtransport-go).

### Install toolchains (Ubuntu)

```bash
# Ensure you have the basic tools
sudo apt install git curl build-essential

# Rust (via rustup — do not use apt, it ships an old version)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Go (replace 1.26.3 with latest from https://go.dev/dl/)
wget https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.3.linux-amd64.tar.gz
rm go1.26.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"
```

### Clone and build

```bash
git clone https://github.com/qbitroot/webtransport-fuzzer
cd webtransport-fuzzer
uv sync

# Build the Go server (one-time)
cd server/webtransport-go
go build -o webtransport-go-server .
cd ../..

# Build the Rust server (one-time; also done automatically on first launch)
cargo build --manifest-path server/wtransport/Cargo.toml --release
```

## Running

```bash
# Fuzz aioquic (Python server)
uv run launch.py aioquic all

# Fuzz wtransport (Rust server)
uv run launch.py wtransport all

# Fuzz webtransport-go (Go server)
uv run launch.py go all

# Fuzz oneshot mode only
uv run launch.py aioquic oneshot

# Resume from a specific test case index
uv run launch.py aioquic all --start-index 500
```

Each run writes `logs/<server>_<mode>_<timestamp>.db` and `logs/<server>_<mode>_<timestamp>.server.log`, then automatically stitches the server log into the DB via `correlate_logs.py`.

## Checking compliance

```bash
uv run check_compliance.py --db logs/<stem>.db
uv run check_compliance.py --db logs/<stem>.db --draft both
```

---

Boofuzz-based fuzzer for the [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/) protocol.

Targets the capsule layer on the CONNECT stream and data transports (bidirectional streams, unidirectional streams, datagrams). Tested against local server implementations in the `server/` directory:

- **`server/aioquic`** — Python echo server using [aioquic](https://github.com/aiortc/aioquic) (draft-03 / GEN1)
- **`server/wtransport`** — Rust echo server using [wtransport](https://github.com/BiagioFesta/wtransport) (draft-09 / GEN3)
- **`server/webtransport-go`** — Go echo server using [webtransport-go](https://github.com/quic-go/webtransport-go) (HTTP/3 over QUIC, self-signed TLS, listens on `0.0.0.0:6002`)

---

---

## Fuzzing modes

### Background: CONNECT stream and capsules

A WebTransport session lives inside an HTTP/3 `CONNECT` request. The HTTP/3 stream carrying that `CONNECT` is the **CONNECT stream** — once the server returns `200`, both sides keep this stream open and use it as the session's _control channel_. The bytes exchanged on it are framed as **capsules** (RFC 9297): `[Type (VarInt)][Length (VarInt)][Payload]`. Capsule types carry session-level signals — `WT_CLOSE_SESSION`, `WT_DRAIN_SESSION`, the flow-control family (`WT_MAX_DATA`, `WT_MAX_STREAMS`, …), and so on. Data is _not_ sent as capsules; it travels on separate WebTransport streams (bidi/uni) and QUIC datagrams owned by the same session.

### Step types

Every multistep scenario is a sequence of these four primitives:

| Step            | What happens                                                                                              |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| `bidi(hex)`     | Opens a bidirectional WebTransport stream, sends payload, awaits echo (1 s timeout; timeout is non-fatal) |
| `uni(hex)`      | Opens a unidirectional stream, sends payload, awaits server-pushed echo on a peer stream                  |
| `datagram(hex)` | Sends a QUIC datagram, awaits echoed datagram                                                             |
| `capsule(hex)`  | Sends a raw capsule on the CONNECT stream (no echo expected)                                              |

Steps execute **sequentially** with normal `await`s and per-step timeouts.

### `--mode oneshot`

Sends a single malformed `[CapsuleType][CapsuleLength][Payload]` blob per connection on the CONNECT stream. A health check (echo probe on a fresh bidirectional stream) runs before each test case; server crashes are detected by handshake failure on the next case.

The corpus is the union of two sub-corpora:

**Spec-typed mutations** — for each canonical capsule type (`WT_CLOSE_SESSION`, `WT_DRAIN_SESSION`, `WT_MAX_DATA`, `WT_MAX_STREAMS` bidi/uni, `WT_DATA_BLOCKED`, `WT_STREAMS_BLOCKED` bidi/uni) a boofuzz Request is built that fuzzes the payload while a `QuicVarInt` sizer keeps `Length` consistent. Payload mutators are `s_dword` (32-bit error code, for CLOSE), `s_string` (UTF-8 message, for CLOSE), and `QuicVarInt` (single VarInt, for the flow-control family). Materialised mutation pool: **1,879 blobs**.

**Structure-agnostic raw mutations** — derived from `ALL_INTERESTING_BYTES`, a list of **85 byte sequences** built by deduplicating the union of: 9 valid capsule type encodings, 28 boundary VarInts, 19 malformed/overlong VarInts, and 41 QUIC + HTTP/3 frame-type bytes (cross-layer type confusion: a parser that demuxes by first-byte prefix can mistake a QUIC `RESET_STREAM` for a capsule type). Three sub-corpora:

| Shape                          | Count           | What it probes                                                           |
| ------------------------------ | --------------- | ------------------------------------------------------------------------ |
| `[T]`                          | 85              | truncation, single-byte garbage                                          |
| `[T][L]` (length but no body)  | 85 × 85 = 7,225 | length / body-length mismatch                                            |
| `[T][len(B)][B]` (well-framed) | 85 × 85 = 7,225 | foreign payload under a real type — including QUIC/HTTP-3 frames as type |

Raw total before dedup: 85 + 7,225 + 7,225 = **14,535**. After dedup (e.g. the empty-bytes entry collapses several combinations): **14,194**.

**Total oneshot test cases: 1,879 + 14,194 = 16,073 pre-dedup → 16,016 unique blobs** (57 collisions between the spec-typed and raw axes).

Oneshot is a **stateless parser fuzzer** for the capsule framing on the CONNECT stream.

### `--mode sc-shuffle`

Executes multi-step scenarios that interleave real data activity with capsule sequences on a single live session. Every mutation is composed of well-formed primitives, so crashes here are unambiguous state-machine bugs (use-after-free, state confusion after close, crash on out-of-order capsules) rather than parser bugs already covered by oneshot.

#### Scenarios

Twelve hand-picked scenarios (`src/boofuzz_definitions.py:511`) drawn from five design categories:

1. **End-to-end teardown** — exercise one or more data paths then close gracefully. _(`bidi_then_shutdown`, `all_transports_then_close`, `close_error_after_data`, `multi_bidi_then_close`, `multi_datagram_then_drain`)_
2. **Control capsule between data** — inject a flow-control or drain capsule in the middle of an otherwise data-only sequence; tests that capsule handling doesn't corrupt stream/datagram processing. _(`capsule_between_bidi`, `drain_mid_data`, `uni_capsule_interleave`)_
3. **Live flow-control changes** — adjust `MAX_DATA`/`MAX_STREAMS` while data is in flight. _(`flow_with_streams`)_
4. **Self-contradicting limits** — set a limit that blocks an action, then perform it; or signal `STREAMS_BLOCKED` and immediately open a stream. _(`contradictory_limits_with_data`, `blocked_then_create`)_
5. **Maximum step diversity** — one of every primitive plus every control capsule; produces the largest permutation surface. _(`kitchen_sink`)_

**Why not just add more scenarios?** The mutation engine already generates every permutation, duplication, omission, repetition, reversal, prohibited-capsule injection, and post-CLOSE follow-up of whatever step list you give it. A new hand-written scenario adds value only if it contains a **structurally new step composition** the operators can't reach from the existing 12 — e.g. a step type none of them use (there are only four), or a control primitive none of them issue (the canonical set is small and fully covered). In practice, new scenarios assembled from the same primitives produce mutations that collide with existing ones during dedup; the marginal coverage approaches zero quickly. The 12 chosen scenarios were picked so each category above is represented at least twice with different step counts, giving the operators dense input variety.

#### Mutation operators

`generate_sequence_mutations` (`src/sequence_mutator.py:109`) applies every operator below to every scenario, then unions and deduplicates:

| #   | Operator                                          | Output count (n = scenario length)                 | Targets                                                                                                                        |
| --- | ------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 0   | identity                                          | 1                                                  | baseline; must pass                                                                                                            |
| 1   | permutations                                      | `min(n!, 5040)`                                    | order-dependent state assumptions                                                                                              |
| 2a  | duplicate-in-place per step                       | n                                                  | duplicate-message handling (e.g. double CLOSE)                                                                                 |
| 2b  | duplicate-at-end per step                         | n                                                  | trailing duplicate after completion                                                                                            |
| 3   | omit each step                                    | n                                                  | missing-prerequisite paths                                                                                                     |
| 4   | step repetition: same step 2× / 5× / 10× in a row | 3n                                                 | duplicate-message handling at the protocol level (e.g. 10 DRAIN capsules sent back-to-back, each with normal per-step timeout) |
| 5   | reversed order                                    | 1                                                  | full inversion                                                                                                                 |
| 6   | prohibited-capsule injection at every position    | 2 × (n + 1)                                        | `WT_MAX_STREAM_DATA` / `WT_STREAM_DATA_BLOCKED` — receipt MUST be a session error per draft-15 §5.4                            |
| 7   | post-CLOSE_SESSION activity                       | 6 follow-ups × (`CLOSE_SESSION` steps in scenario) | use-after-close on a "closed" session                                                                                          |

`MAX_PERMUTATIONS = 5040 = 7!` caps factorial blow-up; `kitchen_sink` (n=6) is the largest at 720 permutations, well under the cap.

**Total: 1,520 test cases** across all 12 scenarios after dedup.

All three server generations (GEN1 draft-03, GEN3 draft-09, GEN4 draft-15) are targeted simultaneously. Unknown capsule types MUST be silently ignored per RFC 9297, so flow-control capsules sent to a GEN1 server are valid test cases.

### `--mode sc-capsule`

Each scenario's setup steps run as legitimate traffic to build server state (open streams, flow-control counters, queued echoes), then the **last step** is replaced with a spec-typed fuzzed capsule. Fuzzes the capsule parser _while the server holds real session state_ — a code path stateless oneshot fuzzing cannot reach.

Test cases = 12 scenarios × 1,879 spec-typed blobs, deduplicated → **22,548 test cases**. First-step injection is omitted (no meaningful state right after `open()`); raw blobs are omitted (overlap with oneshot, too expensive per case).

### `--mode all`

Runs oneshot, sc-shuffle, and sc-capsule in one session, all executed via the same scenario executor (oneshot blobs wrapped as single-step scenarios).

**Total: 40,082 test cases** (16,016 + 1,520 + 22,548 = 40,084 pre-dedup; two collisions).

---

## Server fingerprinting

Before fuzzing, use `server_version.py` to identify which draft generation the target implements:

```bash
uv run server_version.py --no-verify 127.0.0.1 6161
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
uv run correlate_logs.py --log server.log --db boofuzz-results/run_<timestamp>.db
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
  boofuzz_definitions.py  — Tier-A spec-aware + Tier-B raw oneshot corpus;
                            named multistep scenarios; QuicVarInt sizer
  quic_varint_fuzzable.py — custom boofuzz Fuzzable for QUIC VarInts (RFC 9000 §16)
  sequence_mutator.py     — Step / Scenario types; mutation engine; ScenarioRegistry
  fuzzer_connection.py    — boofuzz ITargetConnection; per-step outcome capture
  webtransport_client.py  — aioquic WebTransport client (bidi/uni/datagram/capsule)
  echo_monitor.py         — per-step echo verification, optional fail-on-mismatch
  request_logger.py       — boofuzz monitor that writes test cases to SQLite
  log_db.py               — SQLite schema + access
  server_manager.py       — optional server subprocess lifecycle
correlate_logs.py         — offline log correlation tool
server_version.py         — server draft-version fingerprinting tool
server/
  aioquic/                — Python echo server (draft-03)
  wtransport/             — Rust echo server (draft-09)
  webtransport-go/        — Go echo server (webtransport-go / HTTP3+QUIC)
```

---

## Notes

- Use `uv run` for all commands (manages the venv).
- TLS verification is disabled by default (self-signed certs). Use `--no-verify` with `server_version.py`.
- To test from a browser: install mkcert and launch Chrome with `--origin-to-force-quic-on=127.0.0.1:6000`. Chrome does not support [localhost TLS for HTTP/3](https://news.ycombinator.com/item?id=41748640).
- The boofuzz web UI ports: aioquic=26000, wtransport=26001, go=26002 (set per server in `launch.py`).

---

## Results

Full-corpus `all` mode (40,082 unique test cases; 40,084 pre-dedup, two collisions removed) was run against each target.

| Target                       | Cases  | Distinct log groups | Crashes / panics                | Spec violations                          |
| ---------------------------- | ------ | ------------------- | ------------------------------- | ---------------------------------------- |
| **aioquic** (draft-03)       | 40,082 | 48                  | 0                               | **1** — `WEBTRANSPORT_STREAM` on CONNECT |
| **wtransport** (draft-09)    | 40,082 | 255                 | **7,594 cases / 213 unique outputs** | (panic-class; assert reachable from network) |
| **webtransport-go** (HTTP/3) | 40,082 | 47                  | 0                               | 0                                        |

`Distinct log groups` is the number of unique SHA-256 server-output fingerprints — a rough proxy for behavioural diversity (and for wtransport, the 213 panic-bearing fingerprints reflect different surrounding traffic / stream-ID contexts that hit the same underlying assert).

### Findings summary

- **wtransport** — Reachable `assert!(matches!(frame.kind(), FrameKind::Data))` in `wtransport-proto/src/capsule/mod.rs:38`. Any `Headers`/`Exercise` frame on the CONNECT stream is passed through `validate_frame` but trips the assert in `Capsule::with_frame`, panicking the tokio worker (with a secondary `"Driver worker panic!"` in `driver/mod.rs:233`). 7,594 / 40,082 (≈19%) test cases reproduce it across 213 distinct server output groups.
- **aioquic** — `H3Connection` accepts `WEBTRANSPORT_STREAM` (0x41) on the already-established CONNECT stream (`h3/connection.py:996`), silently re-typing it as a WT data stream with attacker-controlled `session_id`. No crash; the session is silently corrupted and torn down with QUIC code 0x0. Violates draft-ietf-webtrans-http3 §4.2 (`MUST` be `H3_FRAME_ERROR`). Detected via a unique fingerprint containing `RECV_BIDI|stream_id=0` (85 test cases hit it).
- **webtransport-go** — No crashes and no spec-violating fingerprints observed across the full corpus.
