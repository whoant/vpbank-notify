use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

/// JWTs, FCM tokens, share keys and `name=value` / `Bearer` credentials inside text.
static SECRET_PATTERNS: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        r"(?:[A-Za-z0-9_-]+:)?APA91[A-Za-z0-9_-]+",
        r"\b[0-9A-Fa-f]{4}(?:-[0-9A-Fa-f]{4}){3}\b",
        r"(?i)\b(?:Bearer\s+|(?:pin|pinshare|keyshare|jwt|token|auth|p256dh)\s*[:=]\s*)\S+",
    ]
    .map(|pattern| Regex::new(pattern).expect("valid redaction pattern"))
});

/// Copies a push payload with credential-like fields, tokens, share codes and URL
/// query strings replaced, for `--debug` output.
pub(crate) fn redact(value: &Value) -> Value {
    redact_at(value, 0)
}

fn redact_at(value: &Value, depth: usize) -> Value {
    if depth > 24 {
        return Value::String("[depth limit]".into());
    }
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| {
                    let normalized: String = key
                        .chars()
                        .filter(char::is_ascii_alphanumeric)
                        .flat_map(char::to_lowercase)
                        .collect();
                    let sensitive = [
                        "token",
                        "jwt",
                        "password",
                        "secret",
                        "authorization",
                        "cookie",
                        "p256dh",
                        "vapid",
                        "privatekey",
                        "publickey",
                        "cryptokey",
                        "keyshare",
                        "pinshare",
                    ]
                    .iter()
                    .any(|part| normalized.contains(part))
                        || [
                            "pin",
                            "pincode",
                            "auth",
                            "authkey",
                            "apikey",
                            "endpoint",
                            "subscription",
                        ]
                        .contains(&normalized.as_str());
                    (
                        key.clone(),
                        if sensitive {
                            Value::String("[redacted]".into())
                        } else {
                            redact_at(value, depth + 1)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.iter().map(|v| redact_at(v, depth + 1)).collect())
        }
        Value::String(text) => {
            if (text.trim_start().starts_with('{') || text.trim_start().starts_with('['))
                && let Ok(decoded) = serde_json::from_str::<Value>(text)
            {
                return Value::String(redact_at(&decoded, depth + 1).to_string());
            }
            let mut text = text.clone();
            for pattern in SECRET_PATTERNS.iter() {
                text = pattern.replace_all(&text, "[redacted]").into_owned();
            }
            if let Ok(mut url) = reqwest::Url::parse(&text)
                && matches!(url.scheme(), "https" | "http")
            {
                if url.host_str() == Some("fcm.googleapis.com") {
                    return Value::String("[redacted push endpoint]".into());
                }
                let _ = url.set_username("");
                let _ = url.set_password(None);
                if url.query().is_some() {
                    url.set_query(Some("[redacted]"));
                }
                url.set_fragment(None);
                text = url.to_string();
            }
            Value::String(text)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn preserves_transaction_fields_and_removes_nested_credentials() {
        let value = json!({"data":{"amount":"1000","balance":"1234","TokenFB":"synthetic-secret","AuthKey":"synthetic-secret","nested":[{"PinShare":"synthetic-secret"}],"encoded":"{\"jwt\":\"synthetic-secret\",\"amount\":\"1000\"}","url":"https://example.invalid/audio?signature=synthetic-secret"}});
        let result = redact(&value);
        assert_eq!(result["data"]["amount"], "1000");
        assert_eq!(result["data"]["balance"], "1234");
        assert!(!result.to_string().contains("synthetic-secret"));
    }
}
