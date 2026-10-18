//! The `--state` directory: native registration, VPBank session, listener lock
//! and the SQLite database of transactions and push receipts.

use crate::{
    bank::{SavedBankSession, Transaction},
    config::PublicConfig,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use fcm_listener::Registration;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

const DATABASE_FILE: &str = "transactions.sqlite3";
const LOCK_FILE: &str = "listener.lock";
const REGISTRATION_FILE: &str = "native-registration.json";
const BANK_SESSION_FILE: &str = "bank-session.json";
/// Upper bound for the JSON secrets files.
const MAX_SECRET_FILE_LEN: u64 = 128 * 1024;
const HISTORY_LIMIT: std::ops::RangeInclusive<usize> = 1..=10000;
/// Persistent IDs sent with each MCS login so FCM stops redelivering them.
const MAX_ACK_IDS: u32 = 1000;

const SCHEMA: &str = "PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS transactions (fingerprint TEXT PRIMARY KEY, scope TEXT NOT NULL, received_at TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS baselines (scope TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS pushes (sequence INTEGER PRIMARY KEY AUTOINCREMENT, native_scope TEXT NOT NULL, persistent_id TEXT NOT NULL, received_at TEXT NOT NULL, processed INTEGER NOT NULL DEFAULT 0, UNIQUE(native_scope,persistent_id));";

#[derive(Clone)]
pub struct State {
    directory: PathBuf,
}

/// Exclusive lock preventing two listeners from sharing one state directory.
pub struct StateLock {
    _file: File,
}

#[derive(Serialize, Deserialize)]
pub struct CachedRegistration {
    pub config: PublicConfig,
    pub registration: Registration,
}

/// Which push receipts a committed snapshot resolves.
enum Resolve<'a> {
    /// Every receipt up to and including this sequence (a baseline).
    UpTo(i64),
    /// One pending receipt per new row, oldest first (an event snapshot).
    OnePerNewRow(&'a [i64]),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub received_at: String,
    #[serde(flatten)]
    pub transaction: Transaction,
}

impl State {
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path).context("Could not create the state directory")?;
        set_mode(path, 0o700)?;
        let state = Self {
            directory: path.canonicalize()?,
        };
        private_file(&state.path(DATABASE_FILE), false)?;
        state.connection()?.execute_batch(SCHEMA)?;
        Ok(state)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(self.path(DATABASE_FILE))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(connection)
    }

    pub fn lock(&self) -> Result<StateLock> {
        let file = private_file(&self.path(LOCK_FILE), false)?;
        fs2::FileExt::try_lock_exclusive(&file)
            .context("The state directory is in use by another listener")?;
        Ok(StateLock { _file: file })
    }

    pub fn load_registration(&self) -> Result<Option<CachedRegistration>> {
        let Some(bytes) = read_private(&self.path(REGISTRATION_FILE))
            .map_err(|_| anyhow!("The native registration file is invalid"))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            anyhow!("Could not read the native registration; secret details were omitted")
        })
    }

    pub fn save_registration(
        &self,
        config: &PublicConfig,
        registration: &Registration,
    ) -> Result<()> {
        let bytes = secret_json(
            &CachedRegistration {
                config: config.clone(),
                registration: registration.clone(),
            },
            false,
        )?;
        self.write_atomic(REGISTRATION_FILE, &bytes)
            .context("Could not write the native registration file")
    }

    pub fn bank_session_path(&self) -> PathBuf {
        self.path(BANK_SESSION_FILE)
    }

    pub fn load_bank_session(&self) -> Result<Option<SavedBankSession>> {
        let Some(bytes) = read_private(&self.bank_session_path()).map_err(|_| {
            anyhow!("The VPBank session file is invalid; run watch --re-pair to recreate it")
        })?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            anyhow!(
                "Could not read the VPBank session file; run watch --re-pair to recreate it; secret content was omitted"
            )
        })
    }

    pub fn save_bank_session(&self, saved: &SavedBankSession) -> Result<()> {
        let bytes = secret_json(saved, true)
            .map_err(|_| anyhow!("Could not encode the VPBank session file"))?;
        self.write_atomic(BANK_SESSION_FILE, &bytes)
            .context("Could not write the VPBank session file")
    }

    pub fn clear_bank_session(&self) -> Result<()> {
        match fs::remove_file(self.bank_session_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Writes a private file via a temporary file, rename and directory fsync.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let temporary = self.path(&format!(".{name}-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = private_file(&temporary, true)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.path(name))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Records a push and returns its receipt, or `None` if it was already processed.
    /// Pushes without a persistent ID get a unique local one.
    pub(crate) fn record_push(&self, native: &str, id: Option<&str>) -> Result<Option<i64>> {
        let id = id
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("local:{}", uuid::Uuid::new_v4()));
        let connection = self.connection()?;
        connection.execute(
            "INSERT OR IGNORE INTO pushes (native_scope,persistent_id,received_at) VALUES (?1,?2,?3)",
            params![native, id, Utc::now().to_rfc3339()],
        )?;
        let receipt: Option<(i64, bool)> = connection
            .query_row(
                "SELECT sequence,processed FROM pushes WHERE native_scope=?1 AND persistent_id=?2",
                params![native, id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(receipt.and_then(|(sequence, processed)| (!processed).then_some(sequence)))
    }

    /// Highest unprocessed receipt, or 0 when nothing is pending.
    pub(crate) fn pending_watermark(&self, native: &str) -> Result<i64> {
        Ok(self.connection()?.query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM pushes WHERE native_scope=?1 AND processed=0",
            [native],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn pending_receipts(&self, native: &str) -> Result<Vec<i64>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT sequence FROM pushes WHERE native_scope=?1 AND processed=0 ORDER BY sequence",
        )?;
        Ok(statement
            .query_map([native], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Most recent server persistent IDs, acknowledged on the next MCS login.
    pub(crate) fn ack_ids(&self, native: &str) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT persistent_id FROM pushes WHERE native_scope=?1 AND persistent_id NOT LIKE 'local:%' ORDER BY sequence DESC LIMIT ?2",
        )?;
        Ok(statement
            .query_map(params![native, MAX_ACK_IDS], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn has_baseline(&self, scope: &str) -> Result<bool> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM baselines WHERE scope=?1)",
            [scope],
            |row| row.get(0),
        )?)
    }

    /// Stores a baseline snapshot and marks every receipt up to `watermark` processed.
    pub(crate) fn commit_snapshot(
        &self,
        scope: &str,
        native: &str,
        rows: &[Transaction],
        watermark: i64,
    ) -> Result<Vec<StoredTransaction>> {
        self.commit(scope, native, rows, Resolve::UpTo(watermark))
    }

    /// Stores an event snapshot and marks one receipt of `pending` (oldest first)
    /// processed per new row, so a fetch that reveals several transfers resolves
    /// several pushes. Returns the new rows.
    pub(crate) fn commit_event_snapshot(
        &self,
        scope: &str,
        native: &str,
        rows: &[Transaction],
        pending: &[i64],
    ) -> Result<Vec<StoredTransaction>> {
        self.commit(scope, native, rows, Resolve::OnePerNewRow(pending))
    }

    fn commit(
        &self,
        scope: &str,
        native: &str,
        rows: &[Transaction],
        resolve: Resolve<'_>,
    ) -> Result<Vec<StoredTransaction>> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let received_at = Utc::now().to_rfc3339();
        let mut new_rows = Vec::new();
        for row in rows {
            let material = serde_json::to_vec(&(scope, &row.account_group, &row.raw_record))?;
            let fingerprint = format!("{:x}", Sha256::digest(material));
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO transactions VALUES (?1,?2,?3,?4)",
                params![fingerprint, scope, received_at, serde_json::to_string(row)?],
            )?;
            if inserted > 0 {
                new_rows.push(StoredTransaction {
                    received_at: received_at.clone(),
                    transaction: row.clone(),
                });
            }
        }
        transaction.execute("INSERT OR IGNORE INTO baselines VALUES (?1)", [scope])?;
        match resolve {
            Resolve::UpTo(watermark) => {
                transaction.execute(
                    "UPDATE pushes SET processed=1 WHERE native_scope=?1 AND sequence<=?2",
                    params![native, watermark],
                )?;
            }
            Resolve::OnePerNewRow(pending) => {
                for receipt in pending.iter().take(new_rows.len()) {
                    transaction.execute(
                        "UPDATE pushes SET processed=1 WHERE native_scope=?1 AND sequence=?2",
                        params![native, receipt],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(new_rows)
    }

    /// The latest `limit` stored transactions, oldest first.
    pub fn history(&self, limit: usize) -> Result<Vec<StoredTransaction>> {
        if !HISTORY_LIMIT.contains(&limit) {
            bail!("The history limit must be within 1..10000");
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT received_at,record FROM transactions ORDER BY rowid DESC LIMIT ?1")?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut output = Vec::new();
        for row in rows {
            let (received_at, record) = row?;
            output.push(StoredTransaction {
                received_at,
                transaction: serde_json::from_str(&record)?,
            });
        }
        output.reverse();
        Ok(output)
    }
}

/// Reads a small regular file, tightening its permissions to 0600 first.
/// Returns `None` if it does not exist.
///
/// The file is opened once without following symlinks, and every check, the
/// permission change and the read use that handle, so it cannot be swapped
/// for a symlink or another file in between.
fn read_private(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = match open_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_FILE_LEN {
        bail!("not a small regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    // Sized up front so reading never reallocates and leaves a partial copy behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    (&file)
        .take(MAX_SECRET_FILE_LEN + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SECRET_FILE_LEN {
        bail!("not a small regular file");
    }
    Ok(Some(bytes))
}

/// Opens for reading, failing on a symlink. `NONBLOCK` keeps a FIFO planted at
/// the path from hanging the open; it does not affect regular files.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Serializes secrets into a buffer allocated once at its final size, so no
/// reallocation leaves a partial copy in freed memory.
fn secret_json(value: &impl Serialize, pretty: bool) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    /// Counts bytes without storing them.
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let encode = |writer: &mut dyn Write| {
        if pretty {
            serde_json::to_writer_pretty(writer, value)
        } else {
            serde_json::to_writer(writer, value)
        }
    };
    let mut counter = Counter(0);
    encode(&mut counter)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(counter.0));
    encode(&mut *bytes)?;
    Ok(bytes)
}

fn private_file(path: &Path, exclusive: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    set_mode(path, 0o600)?;
    Ok(file)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bank::parse_snapshot;
    use serde_json::json;

    #[test]
    fn persists_deduplicated_records_and_preserves_later_pending_pushes() {
        let directory = tempfile::tempdir().unwrap();
        let state = State::open(directory.path()).unwrap();
        let first = state
            .record_push("native", Some("push-one"))
            .unwrap()
            .unwrap();
        let second = state
            .record_push("native", Some("push-two"))
            .unwrap()
            .unwrap();
        let rows = parse_snapshot(&json!({"d":{"Status":"true","Message":"{\"group\":[\"VPB:18/10/2026 01:00|XX1234|1000VND|00000VND|synthetic\"]}"}})).unwrap();
        assert_eq!(
            state
                .commit_snapshot("scope", "native", &rows, first)
                .unwrap()
                .len(),
            1
        );
        assert!(state.has_baseline("scope").unwrap());
        assert_eq!(state.pending_watermark("native").unwrap(), second);
        assert!(
            state
                .record_push("native", Some("push-one"))
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .commit_snapshot("scope", "native", &rows, second)
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.pending_watermark("native").unwrap(), 0);
        let mut different_group = rows[0].clone();
        different_group.account_group = "different-group".into();
        assert_eq!(
            state
                .commit_snapshot("scope", "native", &[different_group], 0)
                .unwrap()
                .len(),
            1
        );
        drop(state);
        let state = State::open(directory.path()).unwrap();
        assert_eq!(state.history(50).unwrap().len(), 2);
        assert_eq!(state.ack_ids("native").unwrap().len(), 2);
    }

    #[test]
    fn protects_registration_and_prevents_duplicate_listeners() {
        let directory = tempfile::tempdir().unwrap();
        let state = State::open(directory.path()).unwrap();
        let lock = state.lock().unwrap();
        assert!(state.lock().is_err());
        let config = PublicConfig {
            app_id: "1:123:web:abc".into(),
            project_id: "synthetic-project".into(),
            api_key: "synthetic-public".into(),
            sender_id: "123".into(),
        };
        let registration: Registration = serde_json::from_str(r#"{"fcm_token":"synthetic-private-token","gcm":{"android_id":"1","security_token":"2"},"keys":{"public_key":"AQ","private_key":"Ag","auth_secret":"Aw"}}"#).unwrap();
        state.save_registration(&config, &registration).unwrap();
        let loaded = state.load_registration().unwrap().unwrap();
        assert_eq!(loaded.registration.fcm_token, "synthetic-private-token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(directory.path().join("native-registration.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(lock);
        assert!(state.lock().is_ok());
    }
    #[test]
    fn persists_bank_session_privately_and_logout_keeps_native_registration() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        let saved:SavedBankSession=serde_json::from_value(serde_json::json!({"version":1,"native_identity":"native","key_share":"1111-2222-3333-4444","pin_share":"123456","jwt":"synthetic-auth","cookie":"synthetic_session=ok","saved_at":"synthetic"})).unwrap();
        assert!(state.load_bank_session().unwrap().is_none());
        state.save_bank_session(&saved).unwrap();
        drop(state);
        let state = State::open(dir.path()).unwrap();
        assert!(state.load_bank_session().unwrap().is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(state.bank_session_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::write(
            dir.path().join("native-registration.json"),
            "synthetic-native-data",
        )
        .unwrap();
        state.clear_bank_session().unwrap();
        state.clear_bank_session().unwrap();
        assert!(state.load_bank_session().unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("native-registration.json")).unwrap(),
            "synthetic-native-data"
        );
    }
    #[test]
    fn secret_files_must_be_small_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        std::fs::write(
            state.bank_session_path(),
            vec![b' '; MAX_SECRET_FILE_LEN as usize + 1],
        )
        .unwrap();
        assert!(state.load_bank_session().is_err());
        std::fs::remove_file(state.bank_session_path()).unwrap();
        #[cfg(unix)]
        {
            let target = dir.path().join("elsewhere.json");
            std::fs::write(&target, "{}").unwrap();
            std::os::unix::fs::symlink(&target, dir.path().join(REGISTRATION_FILE)).unwrap();
            assert!(state.load_registration().is_err());
        }
    }
    #[test]
    fn invalid_session_json_does_not_expose_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        std::fs::write(
            state.bank_session_path(),
            r#"{"jwt":"synthetic-sensitive-value",BROKEN"#,
        )
        .unwrap();
        let error = match state.load_bank_session() {
            Err(error) => error,
            Ok(_) => panic!("accepted invalid JSON"),
        };
        assert!(!format!("{error:#}").contains("synthetic-sensitive-value"));
    }

    #[test]
    fn secret_json_matches_serde_and_is_allocated_once() {
        let value = json!({"jwt":"synthetic-auth","nested":{"cookie":"a=b; c=d"},"list":[1,2,3]});
        for pretty in [false, true] {
            let bytes = secret_json(&value, pretty).unwrap();
            let expected = if pretty {
                serde_json::to_vec_pretty(&value).unwrap()
            } else {
                serde_json::to_vec(&value).unwrap()
            };
            assert_eq!(&bytes[..], &expected[..]);
            assert_eq!(bytes.capacity(), bytes.len());
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_private_refuses_symlinks_and_special_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular.json");
        fs::write(&regular, b"{}").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(&read_private(&regular).unwrap().unwrap()[..], b"{}");
        assert_eq!(
            fs::metadata(&regular).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = dir.path().join("target");
        fs::write(&target, b"outside").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_private(&link).is_err());
        // The symlink target was neither read nor re-permissioned.
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // Special files are created in-process: spawning a helper would let the
        // child briefly inherit other tests' lock files.
        let socket = dir.path().join("socket.json");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(read_private(&socket).is_err());
        #[cfg(target_os = "linux")]
        {
            // Without `NONBLOCK` this open would wait forever for a writer.
            let fifo = dir.path().join("fifo.json");
            rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RUSR).unwrap();
            assert!(read_private(&fifo).is_err());
        }

        let large = dir.path().join("large.json");
        fs::write(&large, vec![b' '; MAX_SECRET_FILE_LEN as usize + 1]).unwrap();
        assert!(read_private(&large).is_err());

        assert!(
            read_private(&dir.path().join("missing.json"))
                .unwrap()
                .is_none()
        );
    }
}
