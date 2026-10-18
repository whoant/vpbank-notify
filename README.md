# VPBank Notify — Rust native push CLI

A Rust prototype that receives FCM pushes directly and fetches VPBank transaction details on each event. **No browser, Chrome, Python or Node is needed at runtime. There is no bank history polling loop.**

How it works:

```text
Tool's own FCM registration → KeyShare/PinShare → JWT issued by VPBank
                                      ↓
FCM TLS push → BALANCE_CHANGING → fetch the list for that event → print new transactions
```

This is an experimental tool based on a community native client protocol and on requests observed from VPBank's web pages. It is not confirmed to be an external integration API supported by VPBank.

## Build

Requires Rust/Cargo (version pinned in `mise.toml`), `protoc`, a C compiler and OpenSSL development files. Dependency versions are locked in `Cargo.lock`. The FCM part lives in the `fcm-listener` crate (directory of the same name, see [its README](fcm-listener/README.md)), a member of the Cargo workspace at the root, used as a path dependency; keep the directory layout when building.

```sh
cargo build --release --locked
./target/release/vpbank-notify --help
```

On macOS, install `protobuf` and `openssl@3` with Homebrew. Linux needs the matching packages for Protobuf, pkg-config and OpenSSL. The binary is not signed or notarized for wide distribution.

## Prepare the native FCM channel

```sh
./target/release/vpbank-notify --state .state prepare
```

This reads the public Firebase configuration from `https://neo.vpbank.com.vn/assets/js/main.js`, creates a new FCM registration for the tool itself if none exists, then verifies the TLS push login. It never reads cookies, JWTs, FCM tokens or keys from a browser. No share code is needed for this step.

The native registration and decryption keys are stored in the state directory. Do not edit or share that file. Do not use the same state directory for two running listeners.

## Watch transactions

The first time, create a new share code in VPBank NEO right before this step. Later runs reuse the same `--state` directory:

```sh
./target/release/vpbank-notify --state .state watch
```

If there is no valid session, enter KeyShare and PinShare when asked; both are hidden while typing. If a session file exists, the tool verifies and reuses it without pairing again. Never pass them as command-line arguments. The tool follows the two authentication steps observed on the registration page and sends **a new FCM token created by the tool itself**. It reports ready only after the push login and VPBank pairing have both succeeded.

An initial history snapshot becomes the deduplication baseline. Existing transactions are not printed by default; add `--show-existing` to see them. After that, each valid push triggers one fetch of the transaction list. Without events there are no periodic history requests. FCM heartbeats and reconnects keep the push connection alive; they are not bank polling.

```sh
./target/release/vpbank-notify --state .state watch --show-existing
./target/release/vpbank-notify --state .state watch --json
./target/release/vpbank-notify --state .state watch --debug
./target/release/vpbank-notify --state .state history --json
```

`--json` prints JSON Lines for piping into other programs; status messages go to stderr. `--debug` shows push payloads with credentials redacted; they may contain account/transaction details if the sender includes them. `history` only reads data stored locally and never calls the bank.

Press Ctrl+C to stop. KeyShare, PIN, JWT and cookies are stored as readable JSON in `<state>/bank-session.json`, a deliberate choice for debugging. The tool writes the file right after pairing, updates cookies after each successful fetch and reuses it on the next start. If VPBank rejects the saved session with HTTP 401/403, the tool deletes it and asks for a new code; temporary network errors keep the file and do not require pairing again. The meaning of a history response with a non-true `Status` is unknown, so the tool prints the observed value (and, with `--debug`, the response with credentials redacted). When this happens while restoring the session at startup, it asks whether to delete the session and pair again; any answer other than `y`, or no terminal, keeps the file. During `watch` it keeps the file and stops; run `watch --re-pair` if it persists. Credentials are never taken from a browser.

## Do I need to enter a code after a restart?

| Component | Persisted? | On restart |
|---|---|---|
| FCM registration, token and decryption keys | Yes, `native-registration.json` in the `--state` directory | Loaded again; no new registration while it is valid |
| FCM TLS connection | A closed socket cannot be saved | Reconnects automatically |
| History and deduplication records | Yes, SQLite in the same `--state` directory | Local data keeps being used |
| VPBank KeyShare/PIN, JWT and cookies | Yes, `bank-session.json`, mode 0600 on Unix | Re-authenticates with the saved session; asks for a code only if there is no session or it was rejected |

Reuse the exact `--state` path; `.state` is relative to the directory you run the command from. Running from another directory with the default creates a new state. The session file is bound to the FCM registration of its state directory; do not copy it alone into a state with a different registration. The file is plaintext for easier debugging, contains credentials and is ignored by Git; keep it out of source archives and logs.

### Re-pair or delete the session

```sh
./target/release/vpbank-notify --state .state watch --re-pair --show-existing
./target/release/vpbank-notify --state .state logout
```

`--re-pair` discards the current session file and asks for a new code. `logout` only deletes the local VPBank session file and keeps the FCM registration and history; it makes no network call and does not claim to revoke the session on the bank's side.

## Data and limitations

- Observed VPBank pushes only carry a generic `BALANCE_CHANGING` notice. Amount, masked account and description come from a separate transaction list response.
- Only the two observed endpoints are used: `ValidationNonSecureNotificationShare` and `GetNonSecureNotificationShare`. No other endpoints or accounts are probed.
- The meaning of the fourth `|`-separated field is unknown. The tool names it `unverified_field` and **does not call it a balance**. The value `00000VND` in observed samples does not prove a zero balance.
- The list may only be a window of recent notifications. Retention and pagination are undocumented, so it is not guaranteed to be the full ledger.
- Pushes guarantee neither zero latency nor complete delivery. Network loss, sleep, pairing expiry, server changes or coalesced pushes can affect the data.
- When reusing the same share code and state, new rows and pending pushes are caught up before the baseline is refreshed. A new share code gets its own deduplication scope and a fresh baseline; old pushes cannot be reliably attributed to another account.
- SQLite is written before stdout; if the process dies between the two, the row is in `history` but stdout output is not guaranteed exactly once.
- Each push is a generic notice without a transaction ID to match one-to-one with a row. Pushes are processed individually; a push that finds no new row stays pending.
- After a reconnect, the tool may catch up once for that connection event. An event gets at most three requests, including retries for temporary errors or a list that has not updated yet (waits of 1 and 2 seconds). Without a new row, the push stays pending until the next push or reconnect. There is no idle history loop.
- Deduplication uses the account group and the full record string. Without a canonical transaction ID, two identical records cannot be told apart and may be merged. Do not use this as the sole source for payment reconciliation.
- Local receive time and bank transaction time are separate fields. Amounts are kept as strings and never rounded through floating point.
- The state directory uses mode 0700; the native registration, VPBank session and SQLite files use 0600 on Unix. Files are not encrypted; protect the directory and its backups. Hidden code input currently supports macOS/Linux; Windows is not implemented.
- URLs containing share codes, authentication headers, JWTs, FCM tokens, PINs and push keys are never logged. Library and network errors are reduced before display.

## Testing

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Automated fixtures use synthetic data. Live testing needs a new share code and access to your own account. Source fixtures contain no real credentials or bank data.

## References

- [`fcm-listener` crate](fcm-listener/README.md): native FCM registration, message reception over TLS and Web Push decryption.
- [Firebase Messaging request implementation](https://github.com/firebase/firebase-js-sdk/blob/main/packages/messaging/src/internals/requests.ts): the client-side Firebase registration protocol.
- [VPBank registration page](https://neo.vpbank.com.vn/notification.html), [its script](https://neo.vpbank.com.vn/assets/js/main.js), [list page](https://neo.vpbank.com.vn/notification-list.html): sources of the observed bank flow.

## Build directory

You can set `target-dir` in `.cargo/config.toml` to keep the build cache on another drive. Without it, `cargo build` puts the binary at `target/debug/vpbank-notify`. `cargo run --locked -- --state .state watch` lets Cargo pick the right binary.
