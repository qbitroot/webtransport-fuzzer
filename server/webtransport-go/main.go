package main

// ---------------------------------------------------------------------------
// WTFUZZ structured logging
// ---------------------------------------------------------------------------
// Format: WTFUZZ|<conn_idx>|EVENT|key=val|key=val
//
// All structured lines go to stdout and are flushed immediately.
// All other diagnostic output goes to stderr.
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

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

const bindAddr = "0.0.0.0:6002"

// wtfuzz emits a structured WTFUZZ line to stdout.
// fmt.Fprintln on os.Stdout issues a single write(2) syscall, which is
// atomic for lines shorter than PIPE_BUF (4096 bytes on Linux), so no
// mutex or buffering is needed.
func wtfuzz(connIdx uint64, event string, kvs ...string) {
	line := fmt.Sprintf("WTFUZZ|%d|%s", connIdx, event)
	for i := 0; i+1 < len(kvs); i += 2 {
		line += fmt.Sprintf("|%s=%s", kvs[i], kvs[i+1])
	}
	fmt.Fprintln(os.Stdout, line)
}

func main() {
	// All diagnostic output to stderr so it doesn't pollute WTFUZZ stdout.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[webtransport-go] ")

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("failed to generate self-signed cert: %v", err)
	}

	h3Server := &http3.Server{
		Addr: bindAddr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
		},
	}
	webtransport.ConfigureHTTP3Server(h3Server)

	s := &webtransport.Server{
		H3:          h3Server,
		CheckOrigin: func(*http.Request) bool { return true },
	}

	var connCounter atomic.Uint64

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		connIdx := connCounter.Add(1) - 1

		sess, err := s.Upgrade(w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		go handleSession(connIdx, sess)
	})

	wtfuzz(0, "SERVER_READY", "bind", bindAddr)

	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func handleSession(connIdx uint64, sess *webtransport.Session) {
	wtfuzz(connIdx, "SESSION_OPEN")

	ctx := sess.Context()

	// bidi streams
	go func() {
		for {
			stream, err := sess.AcceptStream(ctx)
			if err != nil {
				return
			}
			go handleBidi(connIdx, stream)
		}
	}()

	// uni streams
	go func() {
		for {
			stream, err := sess.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go handleUni(connIdx, sess, stream)
		}
	}()

	// datagrams
	go func() {
		for {
			data, err := sess.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			handleDatagram(connIdx, sess, data)
		}
	}()

	// wait for session to end
	<-ctx.Done()

	wtfuzz(connIdx, "SESSION_CLOSE")
}

func handleBidi(connIdx uint64, stream *webtransport.Stream) {
	wtfuzz(connIdx, "RECV_BIDI")

	// Per-stream deadline so a session-level cancellation (e.g. from a
	// malformed capsule) does not silently abort an in-flight read.
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf, err := io.ReadAll(stream)
	if err != nil {
		var streamErr *webtransport.StreamError
		if isStreamError(err, &streamErr) {
			wtfuzz(connIdx, "STREAM_RESET", "error_code", fmt.Sprintf("%d", streamErr.ErrorCode))
		}
		return
	}

	stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write(buf); err != nil {
		return
	}
	stream.Close()

	wtfuzz(connIdx, "ECHO", "type", "bidi")
}

func handleUni(connIdx uint64, sess *webtransport.Session, recv *webtransport.ReceiveStream) {
	wtfuzz(connIdx, "RECV_UNI")

	// Per-stream deadline so a session-level cancellation does not abort reads.
	recv.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf, err := io.ReadAll(recv)
	if err != nil {
		var streamErr *webtransport.StreamError
		if isStreamError(err, &streamErr) {
			wtfuzz(connIdx, "STREAM_RESET", "error_code", fmt.Sprintf("%d", streamErr.ErrorCode))
		}
		return
	}

	send, err := sess.OpenUniStreamSync(context.Background())
	if err != nil {
		return
	}
	send.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := send.Write(buf); err != nil {
		return
	}
	send.Close()

	wtfuzz(connIdx, "ECHO", "type", "uni")
}

func handleDatagram(connIdx uint64, sess *webtransport.Session, data []byte) {
	wtfuzz(connIdx, "RECV_DATAGRAM")

	if err := sess.SendDatagram(data); err != nil {
		return
	}

	wtfuzz(connIdx, "ECHO", "type", "datagram")
}

// isStreamError checks if err wraps a *webtransport.StreamError.
func isStreamError(err error, target **webtransport.StreamError) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for e := err; e != nil; {
		if se, ok := e.(*webtransport.StreamError); ok {
			*target = se
			return true
		}
		if u, ok := e.(unwrapper); ok {
			e = u.Unwrap()
		} else {
			break
		}
	}
	return false
}

// selfSignedCert generates a self-signed TLS certificate for localhost.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}
