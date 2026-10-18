#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use fcm_listener::Registration;
use std::{
    io::{self, Write},
    path::PathBuf,
};
use tokio::{sync::mpsc, task::JoinHandle};
use vpbank_notify::{
    bank::{BankClient, BankError, BankSession, SharePair, http_client},
    config::PublicConfig,
    engine::{Engine, drive},
    native::{self, PushEvent},
    prompt,
    session::{self, RememberedBank},
    state::{State, StoredTransaction},
};

#[derive(Parser)]
#[command(
    version,
    about = "VPBank native push CLI — no browser, no history polling"
)]
struct Args {
    /// State directory holding the registration, session and history
    #[arg(long, default_value = ".state", global = true)]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the tool's own FCM registration and verify the push login
    Prepare,
    /// Pair with VPBank and receive pushes directly
    Watch(WatchArgs),
    /// Delete the saved VPBank session; keep the FCM registration and history
    Logout,
    /// Read local history; never contacts the bank
    History {
        /// Print JSON Lines
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
    },
}

#[derive(clap::Args)]
struct WatchArgs {
    /// Print JSON Lines on stdout; status messages go to stderr
    #[arg(long)]
    json: bool,
    /// Also print the transactions that already exist at startup
    #[arg(long)]
    show_existing: bool,
    /// Print push payloads with credential fields redacted
    #[arg(long)]
    debug: bool,
    /// Discard the saved VPBank session and enter a new share code
    #[arg(long)]
    re_pair: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Ctrl+C drops `execute`, which aborts the listener and restores the terminal.
    let result = tokio::select! {
        result = execute(args) => result,
        result = tokio::signal::ctrl_c() => result.map_err(Into::into),
    };
    if let Err(error) = result {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn execute(args: Args) -> Result<()> {
    let state = State::open(&args.state)?;
    match args.command {
        Command::History { json, limit } => output(state.history(limit as usize)?, json),
        Command::Logout => {
            let _lock = state.lock()?;
            state.clear_bank_session()?;
            eprintln!(
                "Deleted the VPBank session file. The FCM registration and history are kept."
            );
            Ok(())
        }
        Command::Prepare => {
            let _lock = state.lock()?;
            let (http, config, mut registration) = setup(&state).await?;
            native::check_connection(&http, &mut registration, &config, &state).await?;
            eprintln!("Native FCM registration and TLS login succeeded. VPBank is not paired yet.");
            Ok(())
        }
        Command::Watch(options) => {
            let _lock = state.lock()?;
            let (_, config, registration) = setup(&state).await?;
            watch(&state, config, registration, options).await
        }
    }
}

/// Fetches the public Firebase configuration and loads or creates the registration.
async fn setup(state: &State) -> Result<(reqwest::Client, PublicConfig, Registration)> {
    let http = http_client().context("Could not create the HTTP client")?;
    let config = native::fetch_config(&http).await?;
    let registration = native::prepare(&http, &config, state).await?;
    Ok((http, config, registration))
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Listener = JoinHandle<Result<()>>;

async fn watch(
    state: &State,
    config: PublicConfig,
    registration: Registration,
    options: WatchArgs,
) -> Result<()> {
    let native_scope = native::identity(&registration);
    let (tx, mut rx) = mpsc::channel(64);
    let mut listener = tokio::spawn(native::run(
        registration.clone(),
        config,
        state.clone(),
        tx,
        options.debug,
    ));
    let _guard = AbortOnDrop(listener.abort_handle());
    wait_until_connected(&mut listener, &mut rx).await?;
    eprintln!("Native FCM connected.");

    if options.re_pair {
        state.clear_bank_session()?;
    }
    let (bank, resumed) = match session::resume(state, &native_scope, options.debug).await? {
        Some((bank, rows, pending)) => (bank, Some((rows, pending))),
        None => (
            pair(state, &registration.fcm_token, &native_scope).await?,
            None,
        ),
    };
    let scope = bank.scope();
    let api = RememberedBank::new(bank, state.clone(), native_scope.clone());
    let engine = Engine::new(api, state.clone(), scope, native_scope);
    let initial = match resumed {
        Some((rows, pending)) => {
            engine.bootstrap_from_snapshot(rows, options.show_existing, &pending)
        }
        None => engine.bootstrap(options.show_existing).await,
    };
    output(
        settle_bank_error(state, options.debug, initial)?,
        options.json,
    )?;
    eprintln!(
        "Ready to receive transactions via native push. No history polling. Press Ctrl+C to stop."
    );

    let result = tokio::select! {
        result = drive(engine, rx, |rows| output(rows, options.json)) => result,
        result = &mut listener => match result {
            Ok(Ok(())) => Err(anyhow!("The push channel stopped")),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(anyhow!("The push task stopped")),
        },
    };
    settle_bank_error(state, options.debug, result)
}

/// Waits for the first push login before touching VPBank.
async fn wait_until_connected(
    listener: &mut Listener,
    events: &mut mpsc::Receiver<PushEvent>,
) -> Result<()> {
    loop {
        tokio::select! {
            result = &mut *listener => {
                result.context("The push task stopped")??;
                bail!("The push channel stopped before pairing");
            }
            event = events.recv() => match event {
                Some(PushEvent::Connected { .. }) => return Ok(()),
                Some(PushEvent::Disconnected { reason }) => {
                    eprintln!("Push: {reason}; retrying the connection");
                }
                Some(PushEvent::Notification { .. }) => {}
                None => bail!("The push channel closed"),
            },
        }
    }
}

/// Asks for KeyShare/PinShare, pairs with the tool's own FCM token and saves the session.
async fn pair(state: &State, fcm_token: &str, native_scope: &str) -> Result<BankSession> {
    eprintln!("No valid VPBank session; enter a new share code once.");
    let key = prompt::hidden("KeyShare (hidden): ").await?;
    let pin = prompt::hidden("PinShare (hidden): ").await?;
    let bank = BankClient::new()?
        .pair(SharePair::new(&key, &pin)?, fcm_token)
        .await?;
    // Persist immediately after pairing: a later network error must not lose the new JWT.
    state.save_bank_session(&bank.export(native_scope)?)?;
    eprintln!(
        "Paired with VPBank. Session saved to {}",
        state.bank_session_path().display()
    );
    Ok(bank)
}

/// Deletes the saved session when VPBank rejects it, so the next run asks for a new code.
/// With `--debug`, also shows the redacted response behind a refused history request.
fn settle_bank_error<T>(state: &State, debug: bool, result: Result<T>) -> Result<T> {
    if let Err(error) = &result {
        match error.downcast_ref::<BankError>() {
            Some(BankError::Unauthorized) => state.clear_bank_session()?,
            Some(error) if debug => {
                if let Some(detail) = error.rejection_detail() {
                    eprintln!("VPBank response (credentials redacted): {detail}");
                }
            }
            _ => {}
        }
    }
    result
}

/// Escapes control characters so bank data cannot inject terminal sequences.
fn safe_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn output(rows: Vec<StoredTransaction>, json: bool) -> Result<()> {
    let mut out = io::stdout().lock();
    for row in rows {
        if json {
            serde_json::to_writer(&mut out, &row)?;
            writeln!(out)?;
        } else {
            let t = &row.transaction;
            writeln!(
                out,
                "{} | {} | {} {} | {}",
                safe_text(&t.bank_time),
                safe_text(&t.masked_account),
                safe_text(&t.amount),
                safe_text(&t.currency),
                safe_text(&t.description)
            )?;
        }
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_output_escapes_control_sequences_without_changing_vietnamese() {
        assert_eq!(
            safe_text("Chuyển tiền\n\u{1b}[31m"),
            "Chuyển tiền\\n\\u{1b}[31m"
        );
    }
    #[test]
    fn rejects_history_limit_outside_bounds() {
        assert!(Args::try_parse_from(["tool", "history", "--limit", "0"]).is_err());
        assert!(Args::try_parse_from(["tool", "history", "--limit", "10001"]).is_err());
    }
    #[test]
    fn supports_explicit_repair_and_local_logout() {
        assert!(Args::try_parse_from(["tool", "watch", "--re-pair"]).is_ok());
        assert!(Args::try_parse_from(["tool", "logout"]).is_ok());
    }
}
