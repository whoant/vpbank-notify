use crate::Error;
use crate::error::check_status;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

const INSTALL_API: &str = "https://firebaseinstallations.googleapis.com/v1";
const API_NAME: &str = "Firebase installation";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationRequest<'a> {
    app_id: &'a str,
    auth_version: &'a str,
    fid: &'a str,
    sdk_version: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationResponse {
    auth_token: InstallationAuthToken,
}

#[derive(Deserialize)]
pub struct InstallationAuthToken {
    #[serde(rename = "token")]
    pub value: String,
}

impl InstallationAuthToken {
    /// Creates a Firebase installation and returns its auth token.
    pub async fn request(
        http: &reqwest::Client,
        application_id: &str,
        project_id: &str,
        api_key: &str,
    ) -> Result<Self, Error> {
        let fid = generate_fid();
        let request = InstallationRequest {
            app_id: application_id,
            auth_version: "FIS_v2",
            fid: &fid,
            sdk_version: "w:0.6.4",
        };
        let heartbeat = URL_SAFE_NO_PAD.encode(br#"{"heartbeats": [], "version": 2}"#);

        let response: InstallationResponse = http
            .post(format!("{INSTALL_API}/projects/{project_id}/installations"))
            .json(&request)
            .header("x-firebase-client", heartbeat)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|e| Error::Request(API_NAME, e))
            .and_then(|response| check_status(API_NAME, response))?
            .json()
            .await
            .map_err(|e| Error::Response(API_NAME, e))?;

        Ok(response.auth_token)
    }
}

/// A Firebase installation ID: 17 random bytes with the `0b0111` FID header nibble,
/// base64url-encoded and truncated to 22 characters like the Firebase JS SDK.
fn generate_fid() -> String {
    use rand::RngCore;

    let mut fid = [0u8; 17];
    rand::rng().fill_bytes(&mut fid);
    fid[0] = 0b0111_0000 | (fid[0] & 0b0000_1111);
    let mut encoded = URL_SAFE_NO_PAD.encode(fid);
    encoded.truncate(22);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fid_has_firebase_header_and_length() {
        for _ in 0..64 {
            let fid = generate_fid();
            assert_eq!(fid.len(), 22);
            // The SDK's FID pattern: header nibble 0111 makes the first char c, d, e or f.
            assert!(matches!(fid.as_bytes()[0], b'c'..=b'f'), "{fid}");
        }
    }
}
