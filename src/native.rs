//! The tool's own FCM registration and the push listener loop.

use crate::{
    bank::{bounded_bytes, http_client},
    config::PublicConfig,
    state::State,
};
use anyhow::{Context, Result, anyhow, bail};
use fcm_listener::{
    DataMessage, Message, MessageStream, Registration, new_heartbeat_ack, new_heartbeat_ping,
};
use prost::Message as ProstMessage;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
    time::{Instant, MissedTickBehavior, interval_at, sleep, sleep_until, timeout},
};
use tokio_stream::StreamExt;
use zeroize::Zeroizing;

const CONFIG_SCRIPT_URL: &str = "https://neo.vpbank.com.vn/assets/js/main.js";
const BALANCE_EVENT: &str = "BALANCE_CHANGING";
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(20);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
/// `register3` attempts on one fresh GCM session (waits of 1, 2, 4 and 8 s).
const REGISTER_ATTEMPTS: u32 = 5;

/// Deadline for the server's reply to our last heartbeat.
struct HeartbeatWatch {
    deadline: Option<Instant>,
}

impl HeartbeatWatch {
    fn new() -> Self {
        Self { deadline: None }
    }

    fn sent(&mut self, now: Instant) {
        self.deadline = Some(now + HEARTBEAT_DEADLINE);
    }

    fn acknowledged(&mut self) {
        self.deadline = None;
    }
}

/// Exponential reconnect delay: 1 s doubling up to 60 s.
struct Backoff {
    delay: Duration,
}

impl Backoff {
    const INITIAL: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Self {
            delay: Self::INITIAL,
        }
    }

    fn reset(&mut self) {
        self.delay = Self::INITIAL;
    }

    async fn wait(&mut self) {
        sleep(self.delay).await;
        self.delay = (self.delay * 2).min(MAX_RETRY_DELAY);
    }
}

/// Whether `register3` rejected a session that is just not usable yet.
///
/// Right after a fresh check-in Google often answers `PHONE_REGISTRATION_ERROR`
/// for a few seconds; the same request with the same session then succeeds.
fn registration_not_ready(error: &fcm_listener::Error) -> bool {
    matches!(
        error,
        fcm_listener::Error::DependencyRejection(_, reason) if reason == "PHONE_REGISTRATION_ERROR"
    )
}

/// Requests the GCM token, retrying only while the fresh session is not ready.
async fn request_gcm_token(
    mut request: impl AsyncFnMut() -> Result<String, fcm_listener::Error>,
) -> Result<Zeroizing<String>> {
    let mut backoff = Backoff::new();
    let mut attempt = 1;
    loop {
        match bounded_setup(request()).await? {
            Ok(token) => return Ok(Zeroizing::new(token)),
            Err(error) if registration_not_ready(&error) && attempt < REGISTER_ATTEMPTS => {
                eprintln!(
                    "GCM registration is not ready yet; retrying ({attempt}/{REGISTER_ATTEMPTS})"
                );
                backoff.wait().await;
                attempt += 1;
            }
            Err(error) => return Err(anyhow!(safe_error(&error))),
        }
    }
}

async fn bounded_setup<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    timeout(SETUP_TIMEOUT, future)
        .await
        .map_err(|_| anyhow!("Native registration timed out; request details are not shown"))
}

#[derive(Clone, PartialEq, ProstMessage)]
struct LoginReply {
    #[prost(string, optional, tag = "1")]
    id: Option<String>,
    #[prost(message, optional, tag = "3")]
    error: Option<LoginFailure>,
}

#[derive(Clone, PartialEq, ProstMessage)]
struct LoginFailure {
    #[prost(int32, optional, tag = "1")]
    code: Option<i32>,
}

#[derive(Debug, thiserror::Error)]
#[error("FCM rejected the native login; the registration cannot be used")]
struct LoginRejected;

/// Checks a serialized `mcs.LoginResponse`.
fn verify_login(bytes: &[u8]) -> Result<()> {
    let response = LoginReply::decode(bytes).map_err(|_| anyhow!("Invalid FCM login response"))?;
    if response.id.is_none() {
        bail!("FCM returned an incomplete login response");
    }
    if response.error.is_some() {
        return Err(LoginRejected.into());
    }
    Ok(())
}

fn is_balance_push(payload: &Value, sender: &str) -> bool {
    payload.get("from").and_then(Value::as_str) == Some(sender)
        && payload.pointer("/data/type").and_then(Value::as_str) == Some(BALANCE_EVENT)
}

/// Describes a library error without URLs, headers, tokens, keys or payloads.
fn safe_error(error: &fcm_listener::Error) -> String {
    use fcm_listener::Error;
    match error {
        Error::DependencyFailure(stage, _) | Error::DependencyRejection(stage, _) => {
            format!("Native service failed at step {stage}; sensitive content was omitted")
        }
        Error::Request(stage, _) | Error::Response(stage, _) => {
            format!("Native request failed at step {stage}; URL/headers are not shown")
        }
        Error::Socket(_) => "The TLS push connection was interrupted".into(),
        Error::EmptyPayload | Error::MissingCryptoMetadata(_) => {
            "The push lacks the encryption data needed to process it".into()
        }
        Error::Crypto(stage, _) => {
            format!("Web Push decryption failed at step {stage}; key/payload are not shown")
        }
        Error::Base64Decode(stage, _) => {
            format!("Malformed Web Push Base64 metadata at step {stage}")
        }
        Error::ProtobufDecode(stage, _) => {
            format!("Malformed Web Push protobuf frame at step {stage}")
        }
    }
}

/// Reads the public Firebase configuration from VPBank's page script.
pub async fn fetch_config(http: &reqwest::Client) -> Result<PublicConfig> {
    let response = http
        .get(CONFIG_SCRIPT_URL)
        .send()
        .await
        .map_err(|_| anyhow!("Could not download VPBank's public Firebase configuration"))?;
    let body = bounded_bytes(response).await?;
    PublicConfig::parse_script(
        std::str::from_utf8(&body).context("The Firebase script is not UTF-8")?,
    )
}

/// Stable, non-secret identity of a registration (hash of its FCM token).
pub fn identity(registration: &Registration) -> String {
    format!("{:x}", Sha256::digest(registration.fcm_token.as_bytes()))
}

/// Loads the saved registration, or creates and saves a new one.
pub async fn prepare(
    http: &reqwest::Client,
    config: &PublicConfig,
    state: &State,
) -> Result<Registration> {
    if let Some(cached) = state.load_registration()? {
        if cached.config.app_id != config.app_id
            || cached.config.project_id != config.project_id
            || cached.config.sender_id != config.sender_id
        {
            bail!(
                "The Firebase configuration changed; use a separate state directory for a new registration"
            );
        }
        let keys = &cached.registration.keys;
        if cached.registration.fcm_token.is_empty()
            || keys.private_key.len() != 32
            || keys.public_key.len() != 65
            || keys.auth_secret.len() != 16
        {
            bail!("The saved FCM registration has an invalid format");
        }
        return Ok(cached.registration);
    }
    eprintln!("Creating a new native FCM registration for the tool...");
    let native_error = |e: fcm_listener::Error| anyhow!(safe_error(&e));
    let gcm = fcm_listener::Session::create(http)
        .await
        .map_err(native_error)?;
    let subtype = format!("wp:vpbank-notify-rs#{}", uuid::Uuid::new_v4());
    let gcm_token = request_gcm_token(async || gcm.request_token(http, &subtype).await).await?;
    let installation = fcm_listener::firebase::InstallationAuthToken::request(
        http,
        &config.app_id,
        &config.project_id,
        &config.api_key,
    )
    .await
    .map_err(native_error)?;
    let installation_token = Zeroizing::new(installation.value);
    // Match the Firebase SDK's FIS authorization scheme; never use a browser token.
    let authorization = Zeroizing::new(format!("FIS {}", installation_token.as_str()));
    let fcm = fcm_listener::fcm::Registration::request(
        http,
        &config.project_id,
        &config.api_key,
        None,
        &authorization,
        &gcm_token,
    )
    .await
    .map_err(native_error)?;
    let registration = Registration {
        gcm,
        fcm_token: fcm.fcm_token,
        keys: fcm.keys,
    };
    state.save_registration(config, &registration)?;
    Ok(registration)
}

/// Checks in, opens the MCS connection and waits for a successful login.
async fn connect(
    http: &reqwest::Client,
    registration: &mut Registration,
    config: &PublicConfig,
    state: &State,
) -> Result<MessageStream> {
    let session = registration
        .gcm
        .checkin(http)
        .await
        .map_err(|e| anyhow!(safe_error(&e)))?;
    if session.changed(&registration.gcm) {
        registration.gcm = (*session).clone();
        state.save_registration(config, registration)?;
    }
    let connection = timeout(
        CONNECT_TIMEOUT,
        session.new_connection(state.ack_ids(&identity(registration))?),
    )
    .await
    .map_err(|_| anyhow!("Timed out opening the native push connection"))?
    .map_err(|e| anyhow!(safe_error(&e)))?;
    let mut stream = MessageStream::wrap(connection, &registration.keys);
    timeout(CONNECT_TIMEOUT, async {
        loop {
            match stream
                .next()
                .await
                .context("FCM closed the connection before login")?
                .map_err(|e| anyhow!(safe_error(&e)))?
            {
                Message::LoginResponse(bytes) => return verify_login(&bytes),
                Message::HeartbeatPing => stream
                    .write_all(&new_heartbeat_ack())
                    .await
                    .context("Could not send the heartbeat ack")?,
                Message::StreamError(_) | Message::Data(_) => {
                    bail!("FCM sent data out of the login sequence")
                }
                Message::HeartbeatAck | Message::Other(_, _) => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow!("Timed out waiting for the FCM login confirmation"))??;
    Ok(stream)
}

/// Opens and closes one connection to prove the registration works.
pub async fn check_connection(
    http: &reqwest::Client,
    registration: &mut Registration,
    config: &PublicConfig,
    state: &State,
) -> Result<()> {
    connect(http, registration, config, state).await.map(drop)
}

#[derive(Debug)]
pub enum PushEvent {
    Connected { reconnected: bool },
    Notification { receipt: i64 },
    Disconnected { reason: String },
}

/// What the listener needs to turn data messages into [`PushEvent`]s.
struct PushContext<'a> {
    native: &'a str,
    config: &'a PublicConfig,
    state: &'a State,
    sender: &'a mpsc::Sender<PushEvent>,
    debug: bool,
}

/// Keeps a push connection open forever, reconnecting with backoff.
///
/// Returns `Ok(())` once the receiver is gone, or an error if FCM rejects the login.
pub async fn run(
    mut registration: Registration,
    config: PublicConfig,
    state: State,
    sender: mpsc::Sender<PushEvent>,
    debug: bool,
) -> Result<()> {
    let http = http_client().context("Could not create the native HTTP client")?;
    let native = identity(&registration);
    let context = PushContext {
        native: &native,
        config: &config,
        state: &state,
        sender: &sender,
        debug,
    };
    let mut connected_once = false;
    let mut backoff = Backoff::new();
    loop {
        let reason = match connect(&http, &mut registration, &config, &state).await {
            Err(error) if error.downcast_ref::<LoginRejected>().is_some() => return Err(error),
            Err(error) => error.to_string(),
            Ok(mut stream) => {
                sender
                    .send(PushEvent::Connected {
                        reconnected: connected_once,
                    })
                    .await
                    .context("The listener stopped")?;
                connected_once = true;
                backoff.reset();
                match listen(&mut stream, &context).await? {
                    Some(reason) => reason,
                    None => return Ok(()),
                }
            }
        };
        if sender
            .send(PushEvent::Disconnected { reason })
            .await
            .is_err()
        {
            return Ok(());
        }
        backoff.wait().await;
    }
}

async fn write_frame(stream: &mut MessageStream, frame: &[u8]) -> bool {
    timeout(WRITE_TIMEOUT, stream.write_all(frame))
        .await
        .is_ok_and(|result| result.is_ok())
}

/// Serves one connection. Returns the disconnect reason, or `None` if the receiver is gone.
async fn listen(stream: &mut MessageStream, context: &PushContext<'_>) -> Result<Option<String>> {
    let mut heartbeat = interval_at(Instant::now() + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut watch = HeartbeatWatch::new();
    loop {
        tokio::select! {
            _ = sleep_until(watch.deadline.unwrap_or_else(Instant::now)), if watch.deadline.is_some() => {
                return Ok(Some("FCM did not answer the heartbeat; reopening the connection".into()));
            }
            _ = heartbeat.tick() => {
                // Client heartbeat only; never a bank HTTP call.
                if !write_frame(stream, &new_heartbeat_ping()).await {
                    return Ok(Some("Could not send the FCM heartbeat".into()));
                }
                watch.sent(Instant::now());
            }
            next = stream.next() => match next {
                None => return Ok(Some("The FCM channel closed".into())),
                Some(Err(error @ fcm_listener::Error::Socket(_))) => return Ok(Some(safe_error(&error))),
                Some(Err(error)) => {
                    eprintln!("{}; skipping this frame, no transaction verified", safe_error(&error));
                }
                Some(Ok(Message::HeartbeatAck)) => watch.acknowledged(),
                Some(Ok(Message::HeartbeatPing)) => {
                    if !write_frame(stream, &new_heartbeat_ack()).await {
                        return Ok(Some("Could not send the heartbeat ack".into()));
                    }
                }
                Some(Ok(Message::Data(data))) => {
                    if !handle_data(data, context) {
                        return Ok(None);
                    }
                }
                Some(Ok(Message::StreamError(_))) => return Ok(Some("FCM reported a stream error".into())),
                Some(Ok(Message::LoginResponse(_) | Message::Other(_, _))) => {}
            }
        }
    }
}

/// Records a balance push and notifies the engine. Returns `false` if the receiver is gone.
fn handle_data(data: DataMessage, context: &PushContext<'_>) -> bool {
    let Ok(payload) = serde_json::from_slice::<Value>(&data.body) else {
        eprintln!("The push does not contain valid JSON");
        return true;
    };
    let sender_id = context.config.sender_id.as_str();
    if payload.get("from").and_then(Value::as_str) != Some(sender_id) {
        return true;
    }
    if context.debug {
        eprintln!(
            "Push payload (credential fields redacted): {}",
            crate::debug::redact(&payload)
        );
    }
    if !is_balance_push(&payload, sender_id) {
        return true;
    }
    let receipt = match context
        .state
        .record_push(context.native, data.persistent_id.as_deref())
    {
        Ok(receipt) => receipt,
        // Keep the connection: an unrecorded push is not acknowledged on the next
        // login, so FCM can deliver it again.
        Err(error) => {
            eprintln!("Could not record the push locally ({error}); skipping it");
            return true;
        }
    };
    if let Some(receipt) = receipt {
        // A full queue already guarantees a fetch; the receipt stays pending in SQLite.
        if let Err(mpsc::error::TrySendError::Closed(_)) =
            context.sender.try_send(PushEvent::Notification { receipt })
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn distinguishes_login_success_from_rejection_and_malformed_frames() {
        assert!(verify_login(&[10, 0]).is_ok());
        assert!(verify_login(&[10, 0, 26, 2, 8, 7]).is_err());
        assert!(verify_login(&[255]).is_err());
        assert!(verify_login(&[]).is_err());
    }

    #[test]
    fn unrelated_sender_or_event_never_triggers_bank_history() {
        assert!(is_balance_push(
            &json!({"from":"123","data":{"type":"BALANCE_CHANGING"}}),
            "123"
        ));
        assert!(!is_balance_push(
            &json!({"from":"456","data":{"type":"BALANCE_CHANGING"}}),
            "123"
        ));
        assert!(!is_balance_push(
            &json!({"from":"123","data":{"type":"OTHER"}}),
            "123"
        ));
    }

    #[test]
    fn dependency_rejection_does_not_echo_raw_secrets() {
        let error = fcm_listener::Error::DependencyRejection(
            "FCM registration",
            "token=synthetic-secret".into(),
        );
        assert!(!safe_error(&error).contains("synthetic-secret"));
    }
    #[tokio::test(start_paused = true)]
    async fn reconnect_backoff_doubles_up_to_a_minute_and_resets() {
        let mut backoff = Backoff::new();
        let mut delays = Vec::new();
        for _ in 0..8 {
            let start = Instant::now();
            backoff.wait().await;
            delays.push(start.elapsed().as_secs());
        }
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60]);
        backoff.reset();
        assert_eq!(backoff.delay, Backoff::INITIAL);
    }
    #[tokio::test(start_paused = true)]
    async fn unanswered_heartbeat_has_deadline_and_ack_clears_it() {
        let mut watch = HeartbeatWatch::new();
        let now = Instant::now();
        watch.sent(now);
        assert_eq!(watch.deadline, Some(now + Duration::from_secs(20)));
        watch.acknowledged();
        assert!(watch.deadline.is_none());
    }
    fn not_ready() -> fcm_listener::Error {
        fcm_listener::Error::DependencyRejection(
            "GCM registration",
            "PHONE_REGISTRATION_ERROR".into(),
        )
    }
    #[tokio::test(start_paused = true)]
    async fn gcm_registration_retries_until_the_session_is_ready() {
        let mut calls = 0;
        let start = Instant::now();
        let token = request_gcm_token(async || {
            calls += 1;
            if calls < 3 {
                Err(not_ready())
            } else {
                Ok("synthetic-token".to_owned())
            }
        })
        .await
        .unwrap();
        assert_eq!(token.as_str(), "synthetic-token");
        assert_eq!(calls, 3);
        assert_eq!(start.elapsed(), Duration::from_secs(1 + 2));
    }
    #[tokio::test(start_paused = true)]
    async fn gcm_registration_retries_are_bounded_and_other_errors_fail_fast() {
        let mut calls = 0;
        assert!(
            request_gcm_token(async || {
                calls += 1;
                Err(not_ready())
            })
            .await
            .is_err()
        );
        assert_eq!(calls, REGISTER_ATTEMPTS);
        let mut calls = 0;
        assert!(
            request_gcm_token(async || {
                calls += 1;
                Err(fcm_listener::Error::DependencyRejection(
                    "GCM registration",
                    "AUTHENTICATION_FAILED".into(),
                ))
            })
            .await
            .is_err()
        );
        assert_eq!(calls, 1);
    }
    #[tokio::test(start_paused = true)]
    async fn native_setup_cannot_wait_forever_in_dependency_http_client() {
        let result = tokio::time::timeout(
            Duration::from_secs(31),
            bounded_setup(std::future::pending::<()>()),
        )
        .await;
        assert!(
            result.is_ok(),
            "outer watchdog expired: setup has no bounded deadline"
        );
        assert!(result.unwrap().is_err());
    }
}
