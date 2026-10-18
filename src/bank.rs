//! VPBank NEO notification-share API: pairing, saved sessions and transaction snapshots.

use chrono::NaiveDateTime;
use regex::Regex;
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://neo.vpbank.com.vn";
const VALIDATION_PATH: &str =
    "/cb/odata/ns/authenticationservice/ValidationNonSecureNotificationShare";
const HISTORY_PATH: &str = "/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare";

const SESSION_VERSION: u32 = 1;
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
/// Caps on the diagnostics kept from a refused history response.
const MAX_STATUS_CHARS: usize = 40;
const MAX_DETAIL_CHARS: usize = 2000;

static SHARE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Fa-f0-9]{4}(?:-[A-Fa-f0-9]{4}){3}$").expect("valid share key pattern")
});
static AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([+-]?[0-9]+(?:\.[0-9]+)?)([A-Z]{3})$").expect("valid amount pattern")
});

/// KeyShare/PinShare pair created in VPBank NEO.
pub struct SharePair {
    key: Zeroizing<String>,
    pin: Zeroizing<String>,
}

impl SharePair {
    /// Borrows the input so the caller keeps control of zeroizing it.
    pub fn new(key: &str, pin: &str) -> Result<Self, BankError> {
        let key = Zeroizing::new(key.trim().to_owned());
        let pin = Zeroizing::new(pin.trim().to_owned());
        if !SHARE_KEY.is_match(&key) || pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BankError::InvalidInput);
        }
        Ok(Self { key, pin })
    }

    /// Deduplication scope: a hash of the share key, never the key itself.
    pub fn scope(&self) -> String {
        format!("{:x}", Sha256::digest(self.key.as_bytes()))
    }
}

/// On-disk form of a paired session (`bank-session.json`).
#[derive(Serialize, Deserialize)]
pub struct SavedBankSession {
    version: u32,
    native_identity: String,
    key_share: String,
    pin_share: String,
    jwt: String,
    cookie: String,
    saved_at: String,
}

impl Drop for SavedBankSession {
    fn drop(&mut self) {
        self.key_share.zeroize();
        self.pin_share.zeroize();
        self.jwt.zeroize();
        self.cookie.zeroize();
    }
}

pub struct BankClient {
    client: reqwest::Client,
    base: reqwest::Url,
    cookies: Arc<Jar>,
}

/// An authenticated client able to fetch transaction snapshots.
pub struct BankSession {
    bank: BankClient,
    pair: SharePair,
    jwt: Zeroizing<String>,
}

impl BankClient {
    pub fn new() -> Result<Self, BankError> {
        Self::with_base(ORIGIN.parse().map_err(|_| BankError::Schema)?)
    }

    pub(crate) fn with_base(base: reqwest::Url) -> Result<Self, BankError> {
        let cookies = Arc::new(Jar::default());
        let client = client_builder()
            .cookie_provider(cookies.clone())
            .build()
            .map_err(|_| BankError::Network)?;
        Ok(Self {
            client,
            base,
            cookies,
        })
    }

    /// Rebuilds a session from disk without calling the pairing endpoint.
    pub fn restore(self, saved: SavedBankSession, native: &str) -> Result<BankSession, BankError> {
        if saved.version != SESSION_VERSION {
            return Err(BankError::Schema);
        }
        if saved.native_identity != native {
            return Err(BankError::SavedSessionMismatch);
        }
        if saved.jwt.trim().is_empty() {
            return Err(BankError::MissingAuth);
        }
        sensitive_header(&saved.jwt)?;
        let pair = SharePair::new(&saved.key_share, &saved.pin_share)?;
        if !saved.cookie.is_empty() {
            sensitive_header(&saved.cookie)?;
            for cookie in saved
                .cookie
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if !cookie.contains('=') {
                    return Err(BankError::Schema);
                }
                self.cookies
                    .add_cookie_str(&format!("{cookie}; Path=/"), &self.base);
            }
        }
        Ok(BankSession {
            bank: self,
            pair,
            jwt: Zeroizing::new(saved.jwt.clone()),
        })
    }

    fn url(&self, path: &str) -> Result<reqwest::Url, BankError> {
        self.base.join(path).map_err(|_| BankError::Schema)
    }

    fn get_json(&self, path: &str) -> Result<reqwest::RequestBuilder, BankError> {
        Ok(self
            .client
            .get(self.url(path)?)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json"))
    }

    async fn validate(&self, pair: &SharePair, token: Option<&str>) -> Result<Value, BankError> {
        let mut request = self.get_json(VALIDATION_PATH)?.query(&[
            ("KeyShare", format!("'{}'", pair.key.as_str())),
            ("PinShare", format!("'{}'", pair.pin.as_str())),
        ]);
        if let Some(token) = token {
            request = request.header("TokenFB", sensitive_header(token)?);
        }
        send_json(request).await
    }

    /// Two-step pairing observed on the VPBank registration page: validate the
    /// share pair, then register `fcm_token` and receive a JWT.
    pub async fn pair(self, pair: SharePair, fcm_token: &str) -> Result<BankSession, BankError> {
        let first = self.validate(&pair, None).await?;
        if first.pointer("/d/Status").and_then(Value::as_str) != Some("2") {
            return Err(BankError::InvalidPair);
        }
        let mut second = self.validate(&pair, Some(fcm_token)).await?;
        if second.pointer("/d/Status").and_then(Value::as_str) != Some("1") {
            return Err(BankError::RegistrationRejected);
        }
        let jwt = second
            .pointer_mut("/d/Jwt")
            .map(Value::take)
            .and_then(|v| match v {
                // Move the string out so no unzeroized copy is left behind.
                Value::String(jwt) => Some(Zeroizing::new(jwt)),
                _ => None,
            })
            .filter(|v| !v.trim().is_empty())
            .ok_or(BankError::MissingAuth)?;
        sensitive_header(&jwt)?;
        Ok(BankSession {
            bank: self,
            pair,
            jwt,
        })
    }
}

fn sensitive_header(value: &str) -> Result<HeaderValue, BankError> {
    let mut value = HeaderValue::from_str(value).map_err(|_| BankError::InvalidInput)?;
    value.set_sensitive(true);
    Ok(value)
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("vpbank-notify-rs/0.1")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
}

pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    client_builder().cookie_store(true).build()
}

async fn send_json(request: reqwest::RequestBuilder) -> Result<Value, BankError> {
    let response = request.send().await.map_err(|_| BankError::Network)?;
    let bytes = bounded_bytes(response).await?;
    serde_json::from_slice(&bytes).map_err(|_| BankError::Schema)
}

/// Reads a successful response body, capped at 2 MiB.
pub(crate) async fn bounded_bytes(mut response: reqwest::Response) -> Result<Vec<u8>, BankError> {
    let status = response.status();
    if !status.is_success() {
        return Err(if matches!(status.as_u16(), 401 | 403) {
            BankError::Unauthorized
        } else {
            BankError::Http(status.as_u16())
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| BankError::Network)? {
        if body.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
            return Err(BankError::Schema);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl BankSession {
    pub fn export(&self, native: &str) -> Result<SavedBankSession, BankError> {
        let cookie = self
            .bank
            .cookies
            .cookies(&self.bank.url(HISTORY_PATH)?)
            .map(|header| {
                header
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| BankError::Schema)
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SavedBankSession {
            version: SESSION_VERSION,
            native_identity: native.to_owned(),
            key_share: self.pair.key.to_string(),
            pin_share: self.pair.pin.to_string(),
            jwt: self.jwt.to_string(),
            cookie,
            saved_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn scope(&self) -> String {
        self.pair.scope()
    }

    pub async fn snapshot(&self) -> Result<Vec<Transaction>, BankError> {
        let mut headers = HeaderMap::new();
        headers.insert("AuthKey", sensitive_header(&self.jwt)?);
        headers.insert("KeyShare", sensitive_header(&self.pair.key)?);
        headers.insert("PinShare", sensitive_header(&self.pair.pin)?);
        headers.insert("AccountNumber", HeaderValue::from_static("all"));
        let value = send_json(self.bank.get_json(HISTORY_PATH)?.headers(headers)).await?;
        parse_snapshot(&value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub bank_time: String,
    pub account_group: String,
    pub masked_account: String,
    pub amount: String,
    pub currency: String,
    /// Fourth `|` field; its meaning is unknown, so it is not called a balance.
    pub unverified_field: String,
    pub description: String,
    pub raw_record: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BankError {
    #[error("Saved VPBank session belongs to another FCM registration; pair again")]
    SavedSessionMismatch,
    #[error("Could not write the VPBank session file; credentials are not shown")]
    SessionStorage,
    #[error(
        "KeyShare/PinShare was rejected, has expired or hit a limit; create a new code once so the session can be saved for later runs"
    )]
    InvalidPair,
    #[error("VPBank did not authorize pairing for the native token")]
    RegistrationRejected,
    #[error("VPBank did not return a valid JWT; transaction access cannot be authenticated")]
    MissingAuth,
    #[error("VPBank rejected the session or it has expired; pair again")]
    Unauthorized,
    /// `Status` was not true. Its meaning is undocumented, so the session is kept.
    #[error(
        "VPBank refused the history request (Status={status}); the session was kept, run watch --re-pair if this persists"
    )]
    SnapshotRejected {
        /// The observed `Status`, escaped and truncated
        status: String,
        /// `Message` with credentials redacted; shown only with `--debug`
        detail: String,
    },
    #[error("VPBank HTTP status {0}; details containing credentials were omitted")]
    Http(u16),
    #[error("Could not reach VPBank or the request timed out")]
    Network,
    #[error("VPBank response does not match the observed structure; credentials are not shown")]
    Schema,
    #[error("KeyShare or PinShare has an invalid format")]
    InvalidInput,
}

impl BankError {
    pub fn transient(&self) -> bool {
        matches!(self, Self::Network | Self::Http(429 | 500..=599))
    }

    /// The redacted response behind [`BankError::SnapshotRejected`], for `--debug`.
    pub fn rejection_detail(&self) -> Option<&str> {
        match self {
            Self::SnapshotRejected { detail, .. } => Some(detail),
            _ => None,
        }
    }
}

fn snapshot_rejected(d: &serde_json::Map<String, Value>) -> BankError {
    let status = match d.get("Status") {
        Some(Value::String(status)) => status.clone(),
        Some(other) => other.to_string(),
        None => "missing".into(),
    };
    let message = d.get("Message").cloned().unwrap_or(Value::Null);
    BankError::SnapshotRejected {
        status: status
            .chars()
            .take(MAX_STATUS_CHARS)
            .flat_map(char::escape_debug)
            .collect(),
        // JSON serialization already escapes control characters.
        detail: crate::debug::redact(&message)
            .to_string()
            .chars()
            .take(MAX_DETAIL_CHARS)
            .collect(),
    }
}

fn parse_bank_time(value: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(value, "%d/%m/%Y %H:%M")
        .or_else(|_| NaiveDateTime::parse_from_str(value, "%d/%m/%Y %H:%M:%S"))
        .ok()
}

/// Parses `GetNonSecureNotificationShare`: `d.Message` is a JSON string mapping an
/// account group to `VPB:<time>|<account>|<amount><currency>|<unknown>|<description>`
/// records. Rows are returned oldest first.
///
/// A non-true `Status` is [`BankError::SnapshotRejected`], not `Unauthorized`: its
/// meaning is not documented, so it must not silently delete the saved session.
pub(crate) fn parse_snapshot(value: &Value) -> Result<Vec<Transaction>, BankError> {
    let d = value
        .get("d")
        .and_then(Value::as_object)
        .ok_or(BankError::Schema)?;
    if !matches!(d.get("Status"), Some(Value::String(s)) if s == "true")
        && d.get("Status") != Some(&Value::Bool(true))
    {
        return Err(snapshot_rejected(d));
    }
    let message = d
        .get("Message")
        .and_then(Value::as_str)
        .ok_or(BankError::Schema)?;
    let grouped: Value = serde_json::from_str(message).map_err(|_| BankError::Schema)?;
    if grouped.as_array().is_some_and(Vec::is_empty) {
        return Ok(Vec::new());
    }
    let grouped = grouped.as_object().ok_or(BankError::Schema)?;
    let mut transactions = Vec::new();
    for (account_group, records) in grouped {
        for record in records.as_array().ok_or(BankError::Schema)? {
            let raw_record = record.as_str().ok_or(BankError::Schema)?;
            let fields: Vec<_> = raw_record.splitn(5, '|').collect();
            let [time, account, amount, unverified, description] = fields[..] else {
                return Err(BankError::Schema);
            };
            if account.is_empty() {
                return Err(BankError::Schema);
            }
            let bank_time = time.strip_prefix("VPB:").ok_or(BankError::Schema)?;
            let sort_key = parse_bank_time(bank_time).ok_or(BankError::Schema)?;
            let amount = AMOUNT.captures(amount).ok_or(BankError::Schema)?;
            transactions.push((
                sort_key,
                Transaction {
                    bank_time: bank_time.to_owned(),
                    account_group: account_group.to_owned(),
                    masked_account: account.to_owned(),
                    amount: amount[1].to_owned(),
                    currency: amount[2].to_owned(),
                    unverified_field: unverified.to_owned(),
                    description: description.to_owned(),
                    raw_record: raw_record.to_owned(),
                },
            ));
        }
    }
    transactions.sort_by_key(|(time, _)| *time);
    Ok(transactions.into_iter().map(|(_, row)| row).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::exchange;
    use serde_json::json;

    const KEY: &str = "1111-2222-3333-4444";
    const PIN: &str = "123456";

    fn pair() -> SharePair {
        SharePair::new(KEY, PIN).unwrap()
    }

    #[test]
    fn parses_signed_amount_and_preserves_pipes_without_inventing_a_balance() {
        let value = json!({"d":{"Status":"true","Message":serde_json::to_string(&json!({"masked":["VPB:18/10/2026 01:00|XX1234|-20000VND|00000VND|note|extra"]})).unwrap()}});
        let rows = parse_snapshot(&value).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "-20000");
        assert_eq!(rows[0].currency, "VND");
        assert_eq!(rows[0].description, "note|extra");
        assert_eq!(rows[0].unverified_field, "00000VND");
    }

    #[test]
    fn empty_history_is_valid_but_auth_and_schema_failures_are_errors() {
        assert!(
            parse_snapshot(&json!({"d":{"Status":"true","Message":"{}"}}))
                .unwrap()
                .is_empty()
        );
        for value in [
            json!({"d":{"Status":"true","Message":"not-json"}}),
            json!({"d":{"Status":"true","Message":"{\"a\":[\"broken\"]}"}}),
        ] {
            assert!(matches!(parse_snapshot(&value), Err(BankError::Schema)));
        }
    }

    #[test]
    fn status_false_keeps_the_session_instead_of_reporting_unauthorized() {
        let error = parse_snapshot(&json!({"d":{"Status":"false","Message":"{\"jwt\":\"synthetic-secret\",\"reason\":\"maintenance\"}"}})).unwrap_err();
        assert!(matches!(&error, BankError::SnapshotRejected { status, .. } if status == "false"));
        assert!(!error.transient());
        assert!(error.to_string().contains("Status=false"));
        let detail = error.rejection_detail().unwrap();
        assert!(detail.contains("maintenance"));
        assert!(!detail.contains("synthetic-secret"));
        assert!(!error.to_string().contains("maintenance"));

        let error = parse_snapshot(&json!({"d":{"Status":-1}})).unwrap_err();
        assert!(error.to_string().contains("Status=-1"));
        let error = parse_snapshot(&json!({"d":{"Status":"\u{1b}[31m"}})).unwrap_err();
        assert!(!error.to_string().contains('\u{1b}'));
    }

    #[test]
    fn rejects_malformed_sharing_values_before_network_requests() {
        assert!(SharePair::new(KEY, PIN).is_ok());
        assert!(SharePair::new(" 1111-2222-3333-4444\n", "123456\r\n").is_ok());
        assert!(SharePair::new("wrong", PIN).is_err());
        assert!(SharePair::new(KEY, "bad-pin").is_err());
    }

    #[tokio::test]
    async fn pairs_with_real_native_token_and_preserves_session_cookies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let responses = [
                json!({"d":{"Status":"2"}}),
                json!({"d":{"Status":"1","Jwt":"synthetic-auth"}}),
                json!({"d":{"Status":"true","Message":"{}"}}),
            ];
            for (index, body) in responses.iter().enumerate() {
                let cookie = if index == 0 {
                    "Set-Cookie: synthetic_session=ok; Path=/\r\n"
                } else {
                    ""
                };
                let request = exchange(&listener, "200 OK", cookie, &body.to_string()).await;
                if index < 2 {
                    assert!(request.contains("keyshare=%271111-2222-3333-4444%27"));
                    assert!(request.contains("pinshare=%27123456%27"));
                    assert_eq!(
                        request.contains("tokenfb: synthetic-native-token"),
                        index == 1
                    );
                }
                if index == 1 {
                    assert!(request.contains("cookie: synthetic_session=ok"));
                }
                if index == 2 {
                    assert!(request.starts_with(&format!("get {} ", HISTORY_PATH.to_lowercase())));
                    assert!(request.contains("authkey: synthetic-auth"));
                    assert!(request.contains("keyshare: 1111-2222-3333-4444"));
                    assert!(request.contains("accountnumber: all"));
                }
            }
        });
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let bank = BankClient {
            client,
            cookies: Arc::default(),
            base: format!("http://{address}").parse().unwrap(),
        };
        let session = bank.pair(pair(), "synthetic-native-token").await.unwrap();
        assert!(session.snapshot().await.unwrap().is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn expired_pair_and_missing_jwt_fail_without_exposing_input() {
        for (responses, missing_jwt) in [
            (vec![json!({"d":{"Status":"-1"}})], false),
            (
                vec![
                    json!({"d":{"Status":"2"}}),
                    json!({"d":{"Status":"1","Jwt":null}}),
                ],
                true,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let server = tokio::spawn(async move {
                for body in responses {
                    exchange(&listener, "200 OK", "", &body.to_string()).await;
                }
            });
            let bank = BankClient {
                cookies: Arc::default(),
                client: reqwest::Client::new(),
                base,
            };
            let error = match bank.pair(pair(), "synthetic-native-token").await {
                Ok(_) => panic!("Invalid authorization was accepted"),
                Err(error) => error,
            };
            assert_eq!(matches!(error, BankError::MissingAuth), missing_jwt);
            assert!(!error.to_string().contains(PIN));
            assert!(!error.to_string().contains("1111-2222"));
            assert!(!error.to_string().contains("synthetic-native-token"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn restores_session_without_pairing_and_preserves_history_cookie() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: reqwest::Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let cookies = Arc::new(Jar::default());
        cookies.add_cookie_str("synthetic_session=ok; Path=/", &base);
        let bank = BankClient {
            client: client_builder()
                .cookie_provider(cookies.clone())
                .build()
                .unwrap(),
            base: base.clone(),
            cookies,
        };
        let original = BankSession {
            bank,
            pair: pair(),
            jwt: Zeroizing::new("synthetic-auth".into()),
        };
        let saved = original.export("native-one").unwrap();
        let json = serde_json::to_string(&saved).unwrap();
        drop(original);
        let saved: SavedBankSession = serde_json::from_str(&json).unwrap();
        let restored = BankClient::with_base(base)
            .unwrap()
            .restore(saved, "native-one")
            .unwrap();
        let server = tokio::spawn(async move {
            let request = exchange(
                &listener,
                "200 OK",
                "",
                r#"{"d":{"Status":"true","Message":"{}"}}"#,
            )
            .await;
            assert!(request.starts_with(&format!("get {} ", HISTORY_PATH.to_lowercase())));
            assert!(!request.contains("validationnonsecure"));
            assert!(request.contains("authkey: synthetic-auth"));
            assert!(request.contains("cookie: synthetic_session=ok"));
        });
        assert!(restored.snapshot().await.unwrap().is_empty());
        server.await.unwrap();
    }

    #[test]
    fn refuses_saved_bank_session_for_another_native_registration() {
        let saved: SavedBankSession = serde_json::from_value(json!({"version":1,"native_identity":"one","key_share":KEY,"pin_share":PIN,"jwt":"synthetic-auth","cookie":"","saved_at":"synthetic"})).unwrap();
        let result = BankClient::new().unwrap().restore(saved, "two");
        assert!(matches!(result, Err(BankError::SavedSessionMismatch)));
    }
}
