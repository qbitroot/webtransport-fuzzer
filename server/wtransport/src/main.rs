use anyhow::Result;
use std::time::Duration;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use wtransport::endpoint::IncomingSession;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

// ---------------------------------------------------------------------------
// WTFUZZ structured logging
// ---------------------------------------------------------------------------
// Format: WTFUZZ|<conn_idx>|EVENT|key=val|key=val
//
// All structured lines go to stdout and are flushed immediately.
// All other diagnostic output (tracing) goes to stderr.
//
// Event catalog:
//   SERVER_READY    bind=<host>:<port>
//   SESSION_OPEN    session_id=<id>
//   SESSION_CLOSE   session_id=<id>
//   RECV_BIDI       stream_id=<id>
//   RECV_UNI        stream_id=<id>
//   RECV_DATAGRAM   session_id=<id>
//   ECHO            type=<bidi|uni|datagram>  stream_id=<id> or session_id=<id>
//   STREAM_RESET    stream_id=<id>  error_code=<code>
// ---------------------------------------------------------------------------

macro_rules! wtfuzz {
    ($conn_idx:expr, $event:expr $(, $key:ident = $val:expr)*) => {{
        let mut line = format!("WTFUZZ|{}|{}", $conn_idx, $event);
        $(
            line.push('|');
            line.push_str(&format!("{}={}", stringify!($key), $val));
        )*
        println!("{}", line);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }};
}

const BIND_PORT: u16 = 6161;

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let config = ServerConfig::builder()
        .with_bind_default(BIND_PORT)
        .with_identity(Identity::self_signed(["localhost"]).unwrap())
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let server = Endpoint::server(config)?;

    info!("Server ready!");
    wtfuzz!(0, "SERVER_READY", bind = format!("0.0.0.0:{}", BIND_PORT));

    for id in 0.. {
        let incoming_session = server.accept().await;
        tokio::spawn(
            handle_connection(id, incoming_session).instrument(info_span!("Connection", id))
        );
    }

    Ok(())
}

async fn handle_connection(conn_idx: u64, incoming_session: IncomingSession) {
    let result = handle_connection_impl(conn_idx, incoming_session).await;
    error!("{:?}", result);
}

async fn handle_connection_impl(conn_idx: u64, incoming_session: IncomingSession) -> Result<()> {
    let mut buffer = vec![0; 65536].into_boxed_slice();

    info!("Waiting for session request...");

    let session_request = incoming_session.await?;

    info!(
        "New session: Authority: '{}', Path: '{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection = session_request.accept().await?;

    // Retrieve the actual HTTP/3 session ID (the stream ID of the CONNECT request)
    // so it matches across test runs (unlike pointers or process-lifetime counters).
    let session_id = connection.session_id().into_u64();

    wtfuzz!(conn_idx, "SESSION_OPEN", session_id = session_id);

    info!("Waiting for data from client...");

    let result = run_session(conn_idx, &connection, &mut buffer, session_id).await;

    wtfuzz!(conn_idx, "SESSION_CLOSE", session_id = session_id);

    result
}

/// Read all chunks from a RecvStream until EOF, accumulating into a Vec.
/// Uses the wtransport native read() API (not AsyncRead).
async fn read_all(stream: &mut wtransport::RecvStream, buffer: &mut [u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    loop {
        match stream.read(buffer).await? {
            None => break,                          // stream closed / EOF
            Some(n) => payload.extend_from_slice(&buffer[..n]),
        }
    }
    Ok(payload)
}

async fn run_session(
    conn_idx: u64,
    connection: &wtransport::Connection,
    buffer: &mut Box<[u8]>,
    session_id: u64,
) -> Result<()> {
    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let mut stream = stream?;
                info!("Accepted BI stream");

                let stream_id = stream.1.id().into_u64();
                wtfuzz!(conn_idx, "RECV_BIDI", stream_id = stream_id);

                // Read entire payload then echo it back on the same bidi stream.
                let payload = read_all(&mut stream.1, buffer).await?;
                info!("Received (bi) {} bytes from client", payload.len());

                stream.0.write_all(&payload).await?;
                wtfuzz!(conn_idx, "ECHO", type = "bidi", stream_id = stream_id);
            }
            stream = connection.accept_uni() => {
                let mut stream = stream?;
                info!("Accepted UNI stream");

                let stream_id = stream.id().into_u64();
                wtfuzz!(conn_idx, "RECV_UNI", stream_id = stream_id);

                // Read entire payload then echo it back on a new uni stream.
                let payload = read_all(&mut stream, buffer).await?;
                info!("Received (uni) {} bytes from client", payload.len());

                let mut send_stream = connection.open_uni().await?.await?;
                let echo_stream_id = send_stream.id().into_u64();
                send_stream.write_all(&payload).await?;
                wtfuzz!(conn_idx, "ECHO", type = "uni", stream_id = echo_stream_id);
            }
            dgram = connection.receive_datagram() => {
                let dgram = dgram?;
                info!("Received (dgram) {} bytes from client", dgram.len());

                wtfuzz!(conn_idx, "RECV_DATAGRAM", session_id = session_id);
                connection.send_datagram(&*dgram)?;
                wtfuzz!(conn_idx, "ECHO", type = "datagram", session_id = session_id);
            }
        }
    }
}

fn init_logging() {
    // Default to OFF so no tracing output pollutes stdout (which the fuzzer
    // monitors for WTFUZZ| lines).  The RUST_LOG env var can override this
    // for local debugging, e.g.: RUST_LOG=info cargo run
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::OFF.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}
