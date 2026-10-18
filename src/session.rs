//! Restoring a saved VPBank session and keeping it fresh after each fetch.

use crate::{
    bank::{BankClient, BankError, BankSession, Transaction},
    engine::HistoryApi,
    prompt,
    state::State,
};
use anyhow::Result;

/// A verified session, its first snapshot, and the push receipts pending before that fetch.
pub type ResumedSession = (BankSession, Vec<Transaction>, Vec<i64>);

/// Restores `bank-session.json` and verifies it with one history request.
///
/// Returns `None` when there is no usable session and the user must pair again.
/// Transient failures are errors and keep the file. A refused history request
/// (`Status` not true) has no documented meaning, so the user decides on the
/// terminal whether to delete the session and pair again; `debug` also shows the
/// redacted response.
pub async fn resume(state: &State, native: &str, debug: bool) -> Result<Option<ResumedSession>> {
    resume_with_client(state, native, BankClient::new()?, debug, prompt::confirm).await
}

async fn resume_with_client(
    state: &State,
    native: &str,
    client: BankClient,
    debug: bool,
    confirm: impl AsyncFnOnce(&str) -> bool,
) -> Result<Option<ResumedSession>> {
    let Some(saved) = state.load_bank_session()? else {
        return Ok(None);
    };
    let bank = match client.restore(saved, native) {
        Ok(bank) => bank,
        Err(BankError::SavedSessionMismatch) => {
            state.clear_bank_session()?;
            eprintln!("The VPBank session file belongs to another FCM registration; pair again.");
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let pending_before_fetch = state.pending_receipts(native)?;
    match bank.snapshot().await {
        Ok(rows) => {
            state.save_bank_session(&bank.export(native)?)?;
            eprintln!("Restored and verified the saved VPBank session; no code needed.");
            Ok(Some((bank, rows, pending_before_fetch)))
        }
        Err(BankError::Unauthorized) => {
            state.clear_bank_session()?;
            eprintln!("VPBank rejected the saved session; a new share code is required.");
            Ok(None)
        }
        Err(error @ BankError::SnapshotRejected { .. }) => {
            eprintln!("{error}");
            if debug && let Some(detail) = error.rejection_detail() {
                eprintln!("VPBank response (credentials redacted): {detail}");
            }
            if confirm("Delete the saved session and pair again with a new share code? [y/N] ")
                .await
            {
                state.clear_bank_session()?;
                Ok(None)
            } else {
                Err(error.into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// A [`BankSession`] that persists refreshed cookies after every successful fetch.
pub struct RememberedBank {
    bank: BankSession,
    state: State,
    native: String,
}

impl RememberedBank {
    pub fn new(bank: BankSession, state: State, native: String) -> Self {
        Self {
            bank,
            state,
            native,
        }
    }
}

impl HistoryApi for RememberedBank {
    async fn snapshot(&self) -> Result<Vec<Transaction>, BankError> {
        let rows = self.bank.snapshot().await?;
        self.state
            .save_bank_session(&self.bank.export(&self.native)?)
            .map_err(|_| BankError::SessionStorage)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bank::SavedBankSession;
    use crate::test_server::exchange;
    use serde_json::json;
    use tokio::net::TcpListener;

    fn saved() -> SavedBankSession {
        serde_json::from_value(json!({"version":1,"native_identity":"native","key_share":"1111-2222-3333-4444","pin_share":"123456","jwt":"synthetic-auth","cookie":"synthetic_session=ok","saved_at":"synthetic"})).unwrap()
    }

    /// A state holding `saved()` and a bank client pointed at a local listener.
    async fn fixture() -> (tempfile::TempDir, State, TcpListener, BankClient) {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state.save_bank_session(&saved()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = BankClient::with_base(
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        )
        .unwrap();
        (dir, state, listener, client)
    }

    async fn never_asked(_: &str) -> bool {
        panic!("the user must not be asked")
    }

    #[tokio::test]
    async fn restart_verifies_history_without_pairing_and_refreshes_saved_cookie() {
        let (_dir, state, listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let request = exchange(
                &listener,
                "200 OK",
                "Set-Cookie: synthetic_session=rotated; Path=/\r\n",
                r#"{"d":{"Status":"true","Message":"{}"}}"#,
            )
            .await;
            assert!(request.contains("/getnonsecurenotificationshare "));
            assert!(!request.contains("/validationnonsecure"));
            assert!(request.contains("cookie: synthetic_session=ok"));
        });
        assert!(
            resume_with_client(&state, "native", client, false, never_asked)
                .await
                .unwrap()
                .is_some()
        );
        server.await.unwrap();
        let text = std::fs::read_to_string(state.bank_session_path()).unwrap();
        assert!(text.contains("synthetic_session=rotated"));
    }

    #[tokio::test]
    async fn expired_session_is_removed_but_temporary_server_errors_keep_it() {
        for status in [401, 503] {
            let (_dir, state, listener, client) = fixture().await;
            let server = tokio::spawn(async move {
                exchange(&listener, &format!("{status} Test"), "", "").await;
            });
            let result = resume_with_client(&state, "native", client, false, never_asked).await;
            server.await.unwrap();
            if status == 401 {
                assert!(result.unwrap().is_none());
                assert!(!state.bank_session_path().exists());
            } else {
                assert!(result.is_err());
                assert!(state.bank_session_path().exists());
            }
        }
    }

    #[tokio::test]
    async fn refused_history_deletes_the_session_only_when_the_user_agrees() {
        for agree in [false, true] {
            let (_dir, state, listener, client) = fixture().await;
            let server = tokio::spawn(async move {
                exchange(
                    &listener,
                    "200 OK",
                    "",
                    r#"{"d":{"Status":"false","Message":"{}"}}"#,
                )
                .await;
            });
            let mut asked = false;
            let result = resume_with_client(&state, "native", client, true, async |label: &str| {
                asked = label.contains("[y/N]");
                agree
            })
            .await;
            server.await.unwrap();
            assert!(asked);
            if agree {
                assert!(result.unwrap().is_none());
                assert!(!state.bank_session_path().exists());
            } else {
                let error = result.err().unwrap();
                assert!(matches!(
                    error.downcast_ref::<BankError>(),
                    Some(BankError::SnapshotRejected { status, .. }) if status == "false"
                ));
                assert!(state.bank_session_path().exists());
            }
        }
    }

    #[tokio::test]
    async fn native_identity_mismatch_requests_new_pair_without_bank_calls() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state.save_bank_session(&saved()).unwrap();
        assert!(
            resume_with_client(
                &state,
                "another-native",
                BankClient::new().unwrap(),
                false,
                never_asked
            )
            .await
            .unwrap()
            .is_none()
        );
        assert!(!state.bank_session_path().exists());
    }
}
