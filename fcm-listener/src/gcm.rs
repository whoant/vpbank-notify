use crate::Error;
use crate::error::check_status;
use crate::proto::{checkin, mcs};
use bytes::{BufMut, BytesMut};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use zeroize::Zeroize;

const CHECKIN_URL: &str = "https://android.clients.google.com/checkin";
const REGISTER_URL: &str = "https://android.clients.google.com/c2dm/register3";
const MCS_HOST: &str = "mtalk.google.com";
const MCS_PORT: u16 = 5228;
const MCS_VERSION: u8 = 41;
const CHROME_VERSION: &str = "63.0.3234.0";

/// A GCM device identity obtained from Android check-in.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    // JSON numbers lose precision above 2^53, so both ids are stored as strings.
    #[serde(with = "display_from_str")]
    pub android_id: i64,

    #[serde(with = "display_from_str")]
    pub security_token: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.security_token.zeroize();
    }
}

impl Session {
    async fn request(
        http: &reqwest::Client,
        android_id: Option<i64>,
        security_token: Option<u64>,
    ) -> Result<Self, Error> {
        const API_NAME: &str = "GCM checkin";

        let request = checkin::AndroidCheckinRequest {
            version: Some(3),
            id: android_id,
            security_token,
            user_serial_number: Some(0),
            checkin: checkin::AndroidCheckinProto {
                r#type: Some(3),
                chrome_build: Some(checkin::ChromeBuildProto {
                    platform: Some(2),
                    channel: Some(1),
                    chrome_version: Some(CHROME_VERSION.into()),
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let response = http
            .post(CHECKIN_URL)
            .body(request.encode_to_vec())
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .send()
            .await
            .map_err(|e| Error::Request(API_NAME, e))
            .and_then(|response| check_status(API_NAME, response))?
            .bytes()
            .await
            .map_err(|e| Error::Response(API_NAME, e))?;
        let response = checkin::AndroidCheckinResponse::decode(response)
            .map_err(|e| Error::ProtobufDecode("android checkin response", e))?;

        let android_id = response
            .android_id
            .ok_or(Error::DependencyFailure(
                API_NAME,
                "response is missing android id",
            ))
            .and_then(|id| {
                i64::try_from(id).map_err(|_| {
                    Error::DependencyFailure(
                        API_NAME,
                        "responded with an android id outside the i64 range",
                    )
                })
            })?;
        let security_token = response.security_token.ok_or(Error::DependencyFailure(
            API_NAME,
            "response is missing security token",
        ))?;

        Ok(Self {
            android_id,
            security_token,
        })
    }

    /// Checks in to the device registration service for the first time.
    pub async fn create(http: &reqwest::Client) -> Result<Self, Error> {
        Self::request(http, None, None).await
    }

    /// Checks in with an existing identity, possibly obtaining a new security token.
    pub async fn checkin(&self, http: &reqwest::Client) -> Result<CheckedSession, Error> {
        Self::request(http, Some(self.android_id), Some(self.security_token))
            .await
            .map(CheckedSession)
    }

    /// Registers `app_id` (the GCM `X-subtype`) and returns the GCM token.
    pub async fn request_token(
        &self,
        http: &reqwest::Client,
        app_id: &str,
    ) -> Result<String, Error> {
        const API_NAME: &str = "GCM registration";
        /// Chrome's server key in URL-safe base64
        const SERVER_KEY: &str = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4";

        let android_id = self.android_id.to_string();
        let params = [
            ("app", "org.chromium.linux"),
            ("X-subtype", app_id),
            ("device", &android_id),
            ("sender", SERVER_KEY),
        ];

        let response = http
            .post(REGISTER_URL)
            .form(&params)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("AidLogin {android_id}:{}", self.security_token),
            )
            .send()
            .await
            .map_err(|e| Error::Request(API_NAME, e))?;
        // The status is checked after the body: register3 reports its reason
        // as `Error=...` in the body, often with HTTP 200.
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| Error::Response(API_NAME, e))?;

        parse_register_response(API_NAME, status, &body)
    }
}

/// Parses the `token=<value>` / `Error=<reason>` body returned by `register3`.
///
/// An `Error=` reason wins over the HTTP status; any other body on a non-2xx
/// response is reported by status rather than as malformed.
fn parse_register_response(
    api: &'static str,
    status: reqwest::StatusCode,
    body: &str,
) -> Result<String, Error> {
    match body.trim().split_once('=') {
        Some(("Error", reason)) => Err(Error::DependencyRejection(api, reason.into())),
        Some(("token", token)) if status.is_success() && !token.is_empty() => Ok(token.into()),
        _ if !status.is_success() => Err(Error::DependencyRejection(api, format!("HTTP {status}"))),
        _ => Err(Error::DependencyFailure(api, "malformed response")),
    }
}

/// A session confirmed by a fresh check-in; required to open an MCS connection.
pub struct CheckedSession(Session);

impl CheckedSession {
    /// Whether check-in returned a different identity that should be persisted.
    pub fn changed(&self, from: &Session) -> bool {
        self.0.security_token != from.security_token || self.0.android_id != from.android_id
    }

    fn login_request(&self, received_persistent_id: Vec<String>) -> mcs::LoginRequest {
        let android_id = self.0.android_id.to_string();
        mcs::LoginRequest {
            adaptive_heartbeat: Some(false),
            auth_service: Some(2),
            auth_token: self.0.security_token.to_string(),
            id: format!("chrome-{CHROME_VERSION}"),
            domain: "mcs.android.com".into(),
            device_id: Some(format!("android-{:x}", self.0.android_id)),
            network_type: Some(1),
            resource: android_id.clone(),
            user: android_id,
            use_rmq2: Some(true),
            setting: vec![mcs::Setting {
                name: "new_vc".into(),
                value: "1".into(),
            }],
            received_persistent_id,
            ..Default::default()
        }
    }

    /// Opens the MCS TLS connection and sends the login request.
    ///
    /// `received_persistent_id` acknowledges messages already processed so FCM stops
    /// redelivering them. The login response arrives as the first
    /// [`Message::LoginResponse`](crate::Message::LoginResponse) on the stream.
    pub async fn new_connection(
        &self,
        received_persistent_id: Vec<String>,
    ) -> Result<Connection, Error> {
        let login = self.login_request(received_persistent_id);
        let mut frame = BytesMut::with_capacity(2 + 5 + login.encoded_len());
        frame.put_u8(MCS_VERSION);
        frame.put_u8(crate::push::LOGIN_REQUEST_TAG);
        login
            .encode_length_delimited(&mut frame)
            .expect("BytesMut grows on demand");

        connect(&frame).await.map_err(Error::Socket)
    }
}

impl std::ops::Deref for CheckedSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An authenticated-in-progress MCS TLS stream; wrap it with
/// [`MessageStream::wrap`](crate::MessageStream::wrap).
pub struct Connection(pub(crate) TlsStream<TcpStream>);

async fn connect(login_frame: &[u8]) -> std::io::Result<Connection> {
    let domain = ServerName::try_from(MCS_HOST).map_err(std::io::Error::other)?;
    let stream = TcpStream::connect((MCS_HOST, MCS_PORT)).await?;
    let mut stream = tls_connector()?.connect(domain, stream).await?;
    stream.write_all(login_frame).await?;
    // The server answers with its MCS version byte before the first tagged frame.
    stream.read_u8().await?;
    Ok(Connection(stream))
}

fn tls_connector() -> std::io::Result<tokio_rustls::TlsConnector> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // Use an explicit provider so the process-wide default does not need to be installed.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

mod display_from_str {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
        D: Deserializer<'de>,
    {
        let value = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_serialize_as_strings_without_precision_loss() {
        let session = Session {
            android_id: i64::MAX,
            security_token: u64::MAX,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert_eq!(
            json,
            r#"{"android_id":"9223372036854775807","security_token":"18446744073709551615"}"#
        );
        let decoded: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.android_id, i64::MAX);
        assert_eq!(decoded.security_token, u64::MAX);
        assert!(
            serde_json::from_str::<Session>(r#"{"android_id":1,"security_token":"2"}"#).is_err()
        );
    }

    #[test]
    fn register_response_parsing() {
        use reqwest::StatusCode;
        let ok = StatusCode::OK;
        assert_eq!(
            parse_register_response("t", ok, "token=abc:def=\n").unwrap(),
            "abc:def="
        );
        assert!(matches!(
            parse_register_response("t", ok, "Error=PHONE_REGISTRATION_ERROR"),
            Err(Error::DependencyRejection("t", reason)) if reason == "PHONE_REGISTRATION_ERROR"
        ));
        for body in ["garbage", "unexpected=value", "token="] {
            assert!(matches!(
                parse_register_response("t", ok, body),
                Err(Error::DependencyFailure(..))
            ));
        }
        // A body reason is kept even on an error status.
        assert!(matches!(
            parse_register_response("t", StatusCode::BAD_REQUEST, "Error=AUTHENTICATION_FAILED"),
            Err(Error::DependencyRejection("t", reason)) if reason == "AUTHENTICATION_FAILED"
        ));
        // Otherwise an error status is reported as such, never as a token.
        for body in ["<html>Service Unavailable</html>", "token=abc"] {
            assert!(matches!(
                parse_register_response("t", StatusCode::SERVICE_UNAVAILABLE, body),
                Err(Error::DependencyRejection("t", reason)) if reason == "HTTP 503 Service Unavailable"
            ));
        }
    }

    #[test]
    fn changed_detects_rotated_identity() {
        let stored = Session {
            android_id: 1,
            security_token: 2,
        };
        assert!(!CheckedSession(stored.clone()).changed(&stored));
        let rotated = CheckedSession(Session {
            security_token: 3,
            ..stored.clone()
        });
        assert!(rotated.changed(&stored));
    }

    #[test]
    fn login_request_identifies_as_chrome_device() {
        let session = CheckedSession(Session {
            android_id: 255,
            security_token: 7,
        });
        let login = session.login_request(vec!["p1".into()]);
        assert_eq!(login.device_id.as_deref(), Some("android-ff"));
        assert_eq!(login.user, "255");
        assert_eq!(login.auth_token, "7");
        assert_eq!(login.id, "chrome-63.0.3234.0");
        assert_eq!(login.received_persistent_id, ["p1"]);
    }

    #[test]
    fn tls_connector_builds_without_process_default_provider() {
        tls_connector().unwrap();
    }
}
