use crate::Error;
use crate::error::check_status;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

const FCM_SEND_API: &str = "https://fcm.googleapis.com/fcm/send";
const FCM_REGISTRATION_API: &str = "https://fcmregistrations.googleapis.com/v1";
const API_NAME: &str = "FCM Registration";

fn to_base64<S: Serializer>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&URL_SAFE_NO_PAD.encode(v))
}

fn from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    // `Cow` borrows when it can and owns otherwise, so readers and escaped
    // strings work too, not just in-memory input.
    let encoded = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
    URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(serde::de::Error::custom)
}

/// Result of registering a GCM token as a Web Push endpoint with FCM.
pub struct Registration {
    pub fcm_token: String,
    pub keys: WebPushKeys,
}

impl Registration {
    /// Registers `gcm_token` with FCM using freshly generated Web Push keys.
    ///
    /// `firebase_installation_auth` is sent verbatim in the
    /// `x-goog-firebase-installations-auth` header, so it must already carry the
    /// `FIS ` scheme prefix used by the Firebase SDK.
    pub async fn request(
        http: &reqwest::Client,
        project_id: &str,
        api_key: &str,
        application_pub_key: Option<&str>,
        firebase_installation_auth: &str,
        gcm_token: &str,
    ) -> Result<Self, Error> {
        let keys = WebPushKeys::new().map_err(|e| Error::Crypto("key creation", e))?;
        let endpoint = format!("{FCM_SEND_API}/{gcm_token}");
        let request = RegisterRequest {
            web: WebRegistrationRequest {
                application_pub_key,
                endpoint: &endpoint,
                auth: &keys.auth_secret,
                p256dh: &keys.public_key,
            },
        };

        let response: RegisterResponse = http
            .post(format!(
                "{FCM_REGISTRATION_API}/projects/{project_id}/registrations"
            ))
            .json(&request)
            .header("x-goog-api-key", api_key)
            .header(
                "x-goog-firebase-installations-auth",
                firebase_installation_auth,
            )
            .send()
            .await
            .map_err(|e| Error::Request(API_NAME, e))
            .and_then(|response| check_status(API_NAME, response))?
            .json()
            .await
            .map_err(|e| Error::Response(API_NAME, e))?;

        Ok(Self {
            fcm_token: response.token,
            keys,
        })
    }
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    web: WebRegistrationRequest<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebRegistrationRequest<'a> {
    application_pub_key: Option<&'a str>,
    endpoint: &'a str,
    #[serde(serialize_with = "to_base64")]
    auth: &'a [u8],
    #[serde(serialize_with = "to_base64")]
    p256dh: &'a [u8],
}

#[derive(Deserialize)]
struct RegisterResponse {
    token: String,
}

/// Web Push key material; every field serializes as URL-safe base64 without padding.
#[derive(Clone, Serialize, Deserialize)]
pub struct WebPushKeys {
    /// Uncompressed P-256 public key (65 bytes)
    #[serde(deserialize_with = "from_base64", serialize_with = "to_base64")]
    pub public_key: Vec<u8>,

    /// P-256 private key (32 bytes)
    #[serde(deserialize_with = "from_base64", serialize_with = "to_base64")]
    pub private_key: Vec<u8>,

    /// Random auth secret (16 bytes)
    #[serde(deserialize_with = "from_base64", serialize_with = "to_base64")]
    pub auth_secret: Vec<u8>,
}

impl Drop for WebPushKeys {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.auth_secret.zeroize();
    }
}

impl WebPushKeys {
    fn new() -> Result<Self, ece::Error> {
        let (key_pair, auth_secret) = ece::generate_keypair_and_auth_secret()?;
        let components = key_pair.raw_components()?;
        Ok(Self {
            public_key: components.public_key().into(),
            private_key: components.private_key().into(),
            auth_secret: auth_secret.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_web_push_sizes() {
        let keys = WebPushKeys::new().unwrap();
        assert_eq!(keys.public_key.len(), 65);
        assert_eq!(keys.private_key.len(), 32);
        assert_eq!(keys.auth_secret.len(), 16);
    }

    #[test]
    fn keys_round_trip_as_unpadded_base64url() {
        let keys = WebPushKeys {
            public_key: vec![0xfb, 0xff],
            private_key: vec![2],
            auth_secret: vec![3],
        };
        let json = serde_json::to_string(&keys).unwrap();
        assert_eq!(
            json,
            r#"{"public_key":"-_8","private_key":"Ag","auth_secret":"Aw"}"#
        );
        let decoded: WebPushKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.public_key, keys.public_key);
        assert_eq!(decoded.private_key, keys.private_key);
        assert_eq!(decoded.auth_secret, keys.auth_secret);
        // Streaming input cannot lend borrowed strings.
        let streamed: WebPushKeys = serde_json::from_reader(json.as_bytes()).unwrap();
        assert_eq!(streamed.public_key, keys.public_key);
    }

    #[test]
    fn registration_request_uses_firebase_field_names() {
        let request = RegisterRequest {
            web: WebRegistrationRequest {
                application_pub_key: None,
                endpoint: "https://fcm.googleapis.com/fcm/send/token",
                auth: &[3],
                p256dh: &[1],
            },
        };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({"web": {
                "applicationPubKey": null,
                "endpoint": "https://fcm.googleapis.com/fcm/send/token",
                "auth": "Aw",
                "p256dh": "AQ",
            }})
        );
    }
}
