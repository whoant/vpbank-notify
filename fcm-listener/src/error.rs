#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Dependency failed, i.e. we blame them
    #[error("{0} API {1}")]
    DependencyFailure(&'static str, &'static str),
    /// Dependency rejection, i.e. they blame us
    #[error("{0} API rejected request: {1}")]
    DependencyRejection(&'static str, String),
    /// Received an encrypted message with no decryption params
    #[error("Missing {0} metadata on message")]
    MissingCryptoMetadata(&'static str),
    /// Protobuf deserialization failure, probably a contract change
    #[error("Error decoding {0}: {1}")]
    ProtobufDecode(&'static str, #[source] prost::DecodeError),
    #[error("Received a data message with no payload")]
    EmptyPayload,
    #[error("{0} API request error: {1}")]
    Request(&'static str, #[source] reqwest::Error),
    #[error("{0} API response error: {1}")]
    Response(&'static str, #[source] reqwest::Error),
    #[error("Error decoding {0}: {1}")]
    Base64Decode(&'static str, #[source] base64::DecodeError),
    #[error("Crypto {0} error: {1}")]
    Crypto(&'static str, #[source] ece::Error),
    #[error("TCP error: {0}")]
    Socket(#[source] std::io::Error),
}

/// Rejects non-2xx responses by status only, so error bodies are never echoed.
pub(crate) fn check_status(
    api: &'static str,
    response: reqwest::Response,
) -> Result<reqwest::Response, Error> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(Error::DependencyRejection(api, format!("HTTP {status}")))
    }
}
