# fcm-listener

A Rust crate that receives Firebase Cloud Messaging (FCM) over a native TLS connection (Chrome's MCS protocol) and decrypts Web Push payloads. Version `0.1.0`, not yet published to a registry.

## Layout

```text
fcm-listener/
├── Cargo.toml
├── build.rs          # generates Protobuf code from src/proto/*.proto
└── src/
    ├── lib.rs        # API re-exports and the Registration struct
    ├── gcm.rs        # GCM check-in, register3 token, TLS connection to mtalk.google.com
    ├── firebase.rs   # Firebase Installation token
    ├── fcm.rs        # FCM Web Push registration, WebPushKeys
    ├── push.rs       # MessageStream: MCS framing, Web Push decryption, heartbeats
    ├── error.rs
    └── proto/        # checkin.proto, mcs.proto (Chromium license)
```

## Installation

Add it as a path or git dependency:

```toml
[dependencies]
fcm-listener = { path = "../fcm-listener" }
```

## API

| Item | Purpose |
|---|---|
| `Session::create(http)` | First GCM check-in; returns `android_id` and `security_token` |
| `Session::request_token(http, app_id)` | Obtains a GCM token for the application's `X-subtype` |
| `firebase::InstallationAuthToken::request(http, app_id, project_id, api_key)` | Creates a Firebase Installation and returns its auth token |
| `fcm::Registration::request(http, project_id, api_key, vapid_key, auth, gcm_token)` | Registers for Web Push, generates `WebPushKeys`, returns the FCM token. `auth` must carry the `FIS ` prefix, as in the Firebase SDK |
| `Registration` | What to persist: `fcm_token`, `gcm: Session`, `keys: WebPushKeys` (serde; IDs as strings, keys as unpadded base64url) |
| `Session::checkin(http)` → `CheckedSession` | Re-check-in before every connection; `changed()` tells whether the `Session` must be saved again |
| `CheckedSession::new_connection(persistent_ids)` → `Connection` | Opens TLS to `mtalk.google.com:5228` and sends a `LoginRequest` acknowledging already processed persistent IDs |
| `MessageStream::wrap(connection, &keys)` | `Stream<Item = Result<Message, Error>>`; write heartbeats to the TLS stream through `DerefMut` |
| `new_heartbeat_ping()` / `new_heartbeat_ack()` | Prebuilt heartbeat frames |

`Message` is one of `HeartbeatPing`, `HeartbeatAck`, `LoginResponse(Bytes)`, `Data(DataMessage)`, `StreamError(Bytes)` or `Other(tag, Bytes)`. `DataMessage` holds the decrypted `body` and the `persistent_id`.

The stream ends (`None`) on a `Close` frame, on socket EOF, or right after yielding `Error::Socket` (I/O failure, invalid frame length, or a frame larger than 1 MiB). A data message that fails to decrypt does not close the stream; the application can skip that frame and keep reading.

## Example

```rust
use fcm_listener::{Message, MessageStream, Registration, new_heartbeat_ack};
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

async fn listen(
    http: &reqwest::Client,
    registration: &mut Registration,
    acked: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = registration.gcm.checkin(http).await?;
    if session.changed(&registration.gcm) {
        registration.gcm = (*session).clone(); // persist the Registration again
    }
    let connection = session.new_connection(acked).await?;
    let mut stream = MessageStream::wrap(connection, &registration.keys);
    while let Some(message) = stream.next().await {
        match message? {
            Message::HeartbeatPing => stream.write_all(&new_heartbeat_ack()).await?,
            Message::Data(data) => {
                // store data.persistent_id to acknowledge it on the next connection
                println!("{}", String::from_utf8_lossy(&data.body));
            }
            _ => {}
        }
    }
    Ok(())
}
```

The example omits timeouts, login verification and per-frame error handling for brevity.

## Application responsibilities

The crate does not store credentials, reconnect, or apply timeouts on its own. The application is responsible for:

- timeouts on HTTP requests (pass a configured `reqwest::Client`) and on opening the connection;
- checking the `LoginResponse`, sending periodic heartbeats and detecting missing replies;
- reconnecting, and storing the `Registration` and the persistent ID list securely.

The TLS connection must always be reopened when the process starts. Persisting and reloading the `Registration` reuses the FCM registration and decryption keys without registering again. Credentials for the service that sends the pushes are out of scope.

## Web Push decryption

- `aes128gcm` (RFC 8291) when the `content-encoding` header is `aes128gcm`.
- Legacy `aesgcm` with `dh` from `crypto-key` and `salt` from `encryption`; accepts padded or unpadded base64url, quoted values, multiple `;`-separated parameters and case-insensitive header names.

## TLS

The MCS connection uses `tokio-rustls` with an explicitly supplied `aws-lc-rs` crypto provider and root certificates from `webpki-roots`. The application does not need to call `CryptoProvider::install_default()`.

## Build and test

Requires a recent stable Rust toolchain (edition 2024), `protoc`, a C compiler (for `aws-lc-rs`), OpenSSL development files and, on Linux, `pkg-config` (for `ece`).

```sh
cargo build --locked
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

Tests generate keys and ciphertext at runtime and check frame reassembly with byte-by-byte input; they contain no real tokens or account data. The MCS/check-in protocol definitions keep their own license in `src/proto/LICENSE`.
