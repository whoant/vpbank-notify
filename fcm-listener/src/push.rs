use crate::{Error, WebPushKeys, proto::mcs};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ece::EcKeyComponents;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

// MCS frame tags, as numbered in `mcs.proto`.
const HEARTBEAT_PING_TAG: u8 = 0;
const HEARTBEAT_ACK_TAG: u8 = 1;
pub(crate) const LOGIN_REQUEST_TAG: u8 = 2;
const LOGIN_RESPONSE_TAG: u8 = 3;
const CLOSE_TAG: u8 = 4;
const DATA_MESSAGE_TAG: u8 = 8;
const STREAM_ERROR_TAG: u8 = 10;

/// Upper bound for a single MCS frame; anything larger means the stream is corrupt.
const MAX_FRAME_LEN: usize = 1 << 20;
/// Frame lengths are encoded as a protobuf varint of at most 32 bits.
const MAX_VARINT_LEN: usize = 5;

/// A frame received from the MCS connection.
#[derive(Debug)]
pub enum Message {
    HeartbeatPing,
    HeartbeatAck,
    /// Serialized `mcs.LoginResponse`
    LoginResponse(Bytes),
    /// Decrypted Web Push payload
    Data(DataMessage),
    /// Serialized `mcs.StreamErrorStanza`
    StreamError(Bytes),
    /// Any other frame: raw tag and serialized body
    Other(u8, Bytes),
}

#[derive(Debug)]
pub struct DataMessage {
    pub body: Vec<u8>,
    pub persistent_id: Option<String>,
}

impl DataMessage {
    fn decode(eckey: &EcKeyComponents, auth_secret: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        use prost::Message;

        let message = mcs::DataMessageStanza::decode(bytes)
            .map_err(|e| Error::ProtobufDecode("FCM data message", e))?;
        let raw_data = message.raw_data.ok_or(Error::EmptyPayload)?;
        let app_data = &message.app_data;
        let header = |name: &'static str| {
            app_data
                .iter()
                .filter(move |field| field.key.eq_ignore_ascii_case(name))
                .map(|field| field.value.as_str())
        };

        let body = if header("content-encoding").any(|value| value == "aes128gcm") {
            ece::decrypt(eckey, auth_secret, &raw_data)
                .map_err(|e| Error::Crypto("aes128gcm message decryption", e))?
        } else {
            // Legacy `aesgcm`: parameters live in `key=value;...` headers.
            let parameter = |name: &'static str, key: &str| {
                header(name).find_map(|value| {
                    value.split(';').find_map(|part| {
                        let (k, v) = part.trim().split_once('=')?;
                        (k.trim() == key).then_some(v.trim().trim_matches('"'))
                    })
                })
            };
            let kex = decode_base64(
                parameter("crypto-key", "dh").ok_or(Error::MissingCryptoMetadata("crypto-key"))?,
                "FCM message crypto-key",
            )?;
            let salt = decode_base64(
                parameter("encryption", "salt")
                    .ok_or(Error::MissingCryptoMetadata("encryption"))?,
                "FCM message encryption params",
            )?;

            // The record size default is 4096 and doesn't seem to be overridden for FCM.
            const RECORD_SIZE: u32 = 4096;
            const OPERATION: &str = "message decryption";
            let block = ece::legacy::AesGcmEncryptedBlock::new(&kex, &salt, RECORD_SIZE, raw_data)
                .map_err(|e| Error::Crypto(OPERATION, e))?;
            ece::legacy::decrypt_aesgcm(eckey, auth_secret, &block)
                .map_err(|e| Error::Crypto(OPERATION, e))?
        };

        Ok(Self {
            body,
            persistent_id: message.persistent_id,
        })
    }
}

/// Web Push uses base64url; both padded and unpadded encodings occur in practice.
fn decode_base64(value: &str, stage: &'static str) -> Result<Vec<u8>, Error> {
    URL_SAFE
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(|e| Error::Base64Decode(stage, e))
}

/// Location of the next complete frame header in the receive buffer.
struct FrameHeader {
    tag: u8,
    header_len: usize,
    body_len: usize,
}

/// Parses `tag | varint(len)`; `Ok(None)` means more bytes are needed.
fn frame_header(buf: &[u8]) -> Result<Option<FrameHeader>, Error> {
    let Some((&tag, rest)) = buf.split_first() else {
        return Ok(None);
    };
    let mut body_len = 0usize;
    for (i, &byte) in rest.iter().take(MAX_VARINT_LEN).enumerate() {
        body_len |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if body_len > MAX_FRAME_LEN {
                return Err(invalid_frame("MCS frame exceeds size limit"));
            }
            return Ok(Some(FrameHeader {
                tag,
                header_len: 2 + i,
                body_len,
            }));
        }
    }
    if rest.len() >= MAX_VARINT_LEN {
        return Err(invalid_frame("MCS frame length is not a valid varint"));
    }
    Ok(None)
}

fn invalid_frame(reason: &'static str) -> Error {
    Error::Socket(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
}

/// Splits an MCS byte stream into [`Message`]s, decrypting data messages.
///
/// The stream ends on a `Close` frame, on EOF, or after yielding a socket error.
/// Writes (heartbeats) go straight to the inner transport via `DerefMut`.
pub struct MessageStream<T = TlsStream<TcpStream>> {
    inner: T,
    eckey: EcKeyComponents,
    auth_secret: Zeroizing<Vec<u8>>,
    receive_buffer: BytesMut,
    done: bool,
}

impl MessageStream {
    pub fn wrap(connection: crate::Connection, keys: &WebPushKeys) -> Self {
        Self::new(connection.0, keys)
    }
}

impl<T> MessageStream<T> {
    fn new(inner: T, keys: &WebPushKeys) -> Self {
        Self {
            inner,
            eckey: EcKeyComponents::new(keys.private_key.clone(), keys.public_key.clone()),
            auth_secret: Zeroizing::new(keys.auth_secret.clone()),
            receive_buffer: BytesMut::with_capacity(1024),
            done: false,
        }
    }

    fn finish(&mut self) {
        self.done = true;
        self.receive_buffer.clear();
    }

    fn decode(&self, tag: u8, body: Bytes) -> Result<Message, Error> {
        Ok(match tag {
            HEARTBEAT_PING_TAG => Message::HeartbeatPing,
            HEARTBEAT_ACK_TAG => Message::HeartbeatAck,
            LOGIN_RESPONSE_TAG => Message::LoginResponse(body),
            DATA_MESSAGE_TAG => {
                Message::Data(DataMessage::decode(&self.eckey, &self.auth_secret, &body)?)
            }
            STREAM_ERROR_TAG => Message::StreamError(body),
            _ => Message::Other(tag, body),
        })
    }
}

impl<T: AsyncRead + Unpin> tokio_stream::Stream for MessageStream<T> {
    type Item = Result<Message, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if this.receive_buffer.first() == Some(&CLOSE_TAG) {
                this.finish();
                return Poll::Ready(None);
            }
            match frame_header(&this.receive_buffer) {
                Err(e) => {
                    this.finish();
                    return Poll::Ready(Some(Err(e)));
                }
                Ok(Some(frame)) => {
                    let frame_len = frame.header_len + frame.body_len;
                    if this.receive_buffer.len() >= frame_len {
                        this.receive_buffer.advance(frame.header_len);
                        let body = this.receive_buffer.split_to(frame.body_len).freeze();
                        return Poll::Ready(Some(this.decode(frame.tag, body)));
                    }
                    this.receive_buffer
                        .reserve(frame_len - this.receive_buffer.len());
                }
                Ok(None) => {}
            }

            let read = this.inner.read_buf(&mut this.receive_buffer);
            tokio::pin!(read);
            match ready!(read.poll(cx)) {
                Ok(0) => {
                    // EOF: whatever partial frame is buffered can never complete.
                    this.finish();
                    return Poll::Ready(None);
                }
                Ok(_) => {}
                Err(e) => {
                    this.finish();
                    return Poll::Ready(Some(Err(Error::Socket(e))));
                }
            }
        }
    }
}

impl<T> std::ops::Deref for MessageStream<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for MessageStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn encode_frame(tag: u8, message: &impl prost::Message) -> BytesMut {
    let mut frame = BytesMut::with_capacity(1 + MAX_VARINT_LEN + message.encoded_len());
    frame.put_u8(tag);
    message
        .encode_length_delimited(&mut frame)
        .expect("BytesMut grows on demand");
    frame
}

/// Client heartbeat; the server answers with [`Message::HeartbeatAck`].
pub fn new_heartbeat_ping() -> BytesMut {
    encode_frame(HEARTBEAT_PING_TAG, &mcs::HeartbeatPing::default())
}

/// Reply to a server [`Message::HeartbeatPing`].
pub fn new_heartbeat_ack() -> BytesMut {
    encode_frame(HEARTBEAT_ACK_TAG, &mcs::HeartbeatAck::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use std::collections::VecDeque;
    use tokio::io::ReadBuf;
    use tokio_stream::StreamExt;

    /// Transport that yields one byte per read to exercise frame reassembly.
    struct Trickle(VecDeque<u8>);

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(byte) = self.0.pop_front() {
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    fn keys() -> (WebPushKeys, EcKeyComponents) {
        let (key_pair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();
        let components = key_pair.raw_components().unwrap();
        let keys = WebPushKeys {
            public_key: components.public_key().into(),
            private_key: components.private_key().into(),
            auth_secret: auth_secret.into(),
        };
        (keys, components)
    }

    fn raw_frame(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![tag];
        prost::encoding::encode_varint(body.len() as u64, &mut frame);
        frame.extend_from_slice(body);
        frame
    }

    fn stream(bytes: Vec<u8>, keys: &WebPushKeys) -> MessageStream<Trickle> {
        MessageStream::new(Trickle(bytes.into()), keys)
    }

    #[test]
    fn heartbeat_frames_are_empty_messages() {
        assert_eq!(&new_heartbeat_ping()[..], [HEARTBEAT_PING_TAG, 0]);
        assert_eq!(&new_heartbeat_ack()[..], [HEARTBEAT_ACK_TAG, 0]);
    }

    #[test]
    fn decrypts_legacy_unpadded_metadata_and_modern_webpush() {
        let (keys, components) = keys();
        let body = br#"{"from":"123","data":{"type":"SYNTHETIC"}}"#;
        let encrypted =
            ece::legacy::encrypt_aesgcm(components.public_key(), &keys.auth_secret, body).unwrap();
        let message = mcs::DataMessageStanza {
            from: "123".into(),
            category: "synthetic".into(),
            persistent_id: Some("one".into()),
            raw_data: Some(URL_SAFE_NO_PAD.decode(encrypted.body()).unwrap()),
            app_data: encrypted
                .headers(None)
                .into_iter()
                .map(|(key, value)| mcs::AppData {
                    key: key.to_ascii_lowercase(),
                    value,
                })
                .collect(),
            ..Default::default()
        };
        let decoded =
            DataMessage::decode(&components, &keys.auth_secret, &message.encode_to_vec()).unwrap();
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.persistent_id.as_deref(), Some("one"));

        let modern = ece::encrypt(components.public_key(), &keys.auth_secret, body).unwrap();
        let message = mcs::DataMessageStanza {
            raw_data: Some(modern),
            app_data: vec![mcs::AppData {
                key: "Content-Encoding".into(),
                value: "aes128gcm".into(),
            }],
            ..message
        };
        let decoded =
            DataMessage::decode(&components, &keys.auth_secret, &message.encode_to_vec()).unwrap();
        assert_eq!(decoded.body, body);
    }

    #[test]
    fn accepts_padded_quoted_legacy_parameters() {
        let (keys, components) = keys();
        let body = b"padded";
        let encrypted =
            ece::legacy::encrypt_aesgcm(components.public_key(), &keys.auth_secret, body).unwrap();
        let headers: Vec<_> = encrypted.headers(None).into_iter().collect();
        let value = |name: &str| {
            let (_, value) = headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .unwrap();
            value.clone()
        };
        // Re-encode the leading `key=value` with padding and quotes, keeping e.g. `;rs=4096`.
        let pad = |header: &str| {
            let (param, rest) = header.split_once(';').unwrap_or((header, ""));
            let (key, value) = param.split_once('=').unwrap();
            let padded = URL_SAFE.encode(URL_SAFE_NO_PAD.decode(value).unwrap());
            format!("{key}=\"{padded}\";{rest}")
        };
        let message = mcs::DataMessageStanza {
            raw_data: Some(URL_SAFE_NO_PAD.decode(encrypted.body()).unwrap()),
            app_data: vec![
                mcs::AppData {
                    key: "Crypto-Key".into(),
                    value: format!("p256ecdsa=ignored; {}", pad(&value("crypto-key"))),
                },
                mcs::AppData {
                    key: "Encryption".into(),
                    value: pad(&value("encryption")),
                },
            ],
            ..Default::default()
        };
        let decoded =
            DataMessage::decode(&components, &keys.auth_secret, &message.encode_to_vec()).unwrap();
        assert_eq!(decoded.body, body);
    }

    #[test]
    fn data_message_errors_are_typed() {
        let (keys, components) = keys();
        let empty = mcs::DataMessageStanza::default().encode_to_vec();
        assert!(matches!(
            DataMessage::decode(&components, &keys.auth_secret, &empty),
            Err(Error::EmptyPayload)
        ));
        let no_metadata = mcs::DataMessageStanza {
            raw_data: Some(vec![1, 2, 3]),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(matches!(
            DataMessage::decode(&components, &keys.auth_secret, &no_metadata),
            Err(Error::MissingCryptoMetadata("crypto-key"))
        ));
        assert!(matches!(
            DataMessage::decode(&components, &keys.auth_secret, &[0xff]),
            Err(Error::ProtobufDecode(..))
        ));
    }

    #[tokio::test]
    async fn reassembles_fragmented_frames_in_order() {
        let (keys, components) = keys();
        let payload = b"hello";
        let data = mcs::DataMessageStanza {
            persistent_id: Some("p1".into()),
            raw_data: Some(
                ece::encrypt(components.public_key(), &keys.auth_secret, payload).unwrap(),
            ),
            app_data: vec![mcs::AppData {
                key: "content-encoding".into(),
                value: "aes128gcm".into(),
            }],
            ..Default::default()
        };
        // Larger than the initial buffer and needs a two-byte length varint.
        let large = vec![7u8; 5000];

        let mut bytes = Vec::new();
        bytes.extend(raw_frame(HEARTBEAT_PING_TAG, &[]));
        bytes.extend(raw_frame(LOGIN_RESPONSE_TAG, b"login"));
        bytes.extend(raw_frame(DATA_MESSAGE_TAG, &data.encode_to_vec()));
        bytes.extend(raw_frame(HEARTBEAT_ACK_TAG, &[]));
        bytes.extend(raw_frame(7, &large));
        bytes.extend(raw_frame(STREAM_ERROR_TAG, b"err"));
        bytes.extend(raw_frame(CLOSE_TAG, &[]));
        bytes.extend(raw_frame(HEARTBEAT_PING_TAG, &[]));

        let mut stream = stream(bytes, &keys);
        assert!(matches!(
            stream.next().await,
            Some(Ok(Message::HeartbeatPing))
        ));
        assert!(
            matches!(stream.next().await, Some(Ok(Message::LoginResponse(b))) if &b[..] == b"login")
        );
        match stream.next().await {
            Some(Ok(Message::Data(m))) => {
                assert_eq!(m.body, payload);
                assert_eq!(m.persistent_id.as_deref(), Some("p1"));
            }
            other => panic!("expected data message, got {other:?}"),
        }
        assert!(matches!(
            stream.next().await,
            Some(Ok(Message::HeartbeatAck))
        ));
        assert!(matches!(stream.next().await, Some(Ok(Message::Other(7, b))) if b == large));
        assert!(
            matches!(stream.next().await, Some(Ok(Message::StreamError(b))) if &b[..] == b"err")
        );
        // Close ends the stream even though more frames follow.
        assert!(stream.next().await.is_none());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn bad_data_message_does_not_end_stream() {
        let (keys, _) = keys();
        let mut bytes = raw_frame(DATA_MESSAGE_TAG, &[0xff]);
        bytes.extend(raw_frame(HEARTBEAT_PING_TAG, &[]));
        let mut stream = stream(bytes, &keys);
        assert!(matches!(
            stream.next().await,
            Some(Err(Error::ProtobufDecode(..)))
        ));
        assert!(matches!(
            stream.next().await,
            Some(Ok(Message::HeartbeatPing))
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn eof_mid_frame_ends_stream() {
        let (keys, _) = keys();
        let mut bytes = raw_frame(LOGIN_RESPONSE_TAG, b"truncated");
        bytes.truncate(5);
        assert!(stream(bytes, &keys).next().await.is_none());
    }

    #[tokio::test]
    async fn corrupt_frame_length_is_a_socket_error() {
        let (keys, _) = keys();
        for bytes in [
            vec![LOGIN_RESPONSE_TAG, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            raw_frame(LOGIN_RESPONSE_TAG, &vec![0; MAX_FRAME_LEN + 1]),
        ] {
            let mut stream = stream(bytes, &keys);
            assert!(matches!(stream.next().await, Some(Err(Error::Socket(_)))));
            assert!(stream.next().await.is_none());
        }
    }
}
