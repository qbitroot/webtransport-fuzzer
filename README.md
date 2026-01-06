# webtransport-fuzzer

Boofuzz-based WebTransport protocol fuzzer.

Tested against a local server (see server directory), based on [w3c/webtransport ipv4_echo_server.py](https://github.com/w3c/webtransport/blob/main/samples/echo/py-server/ipv4_echo_server.py).

## Current progress

[![asciicast](https://asciinema.org/a/WYtY0LEHRUk9pH29YYNTZSugk.svg)](https://asciinema.org/a/WYtY0LEHRUk9pH29YYNTZSugk)

---

Note for server: if you want to test the server locally from the browser, after installing mkcert, run chrome with `--origin-to-force-quic-on=127.0.0.1:6161` - Chrome does not support [localhost TLS certificates for HTTP/3](https://news.ycombinator.com/item?id=41748640).
