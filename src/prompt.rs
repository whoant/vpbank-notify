//! Unix terminal input (hidden or visible) with cancellation-safe terminal restoration.
#[cfg(unix)]
mod unix {
    use anyhow::{Context, Result, bail};
    use rustix::{
        fs::{OFlags, fcntl_getfl, fcntl_setfl},
        termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr},
    };
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
    };
    use zeroize::Zeroizing;
    const MAX_INPUT: usize = 128;
    const CHUNK: usize = 128;
    struct TtyGuard {
        file: File,
        original: Termios,
    }
    impl Drop for TtyGuard {
        fn drop(&mut self) {
            // Also discard unfinished secret input before returning control to the shell.
            let _ = tcsetattr(&self.file, OptionalActions::Flush, &self.original);
        }
    }
    pub async fn hidden(label: &str) -> Result<Zeroizing<String>> {
        read_line(label, false).await
    }
    /// Asks a yes/no question; no terminal, EOF or any answer but y/yes is "no".
    pub async fn confirm(label: &str) -> bool {
        read_line(label, true)
            .await
            .is_ok_and(|answer| super::is_yes(&answer))
    }
    async fn read_line(label: &str, echo: bool) -> Result<Zeroizing<String>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("An interactive terminal is required for this input")?;
        let original = tcgetattr(&file).context("Reading the terminal settings")?;
        fcntl_setfl(&file, fcntl_getfl(&file)? | OFlags::NONBLOCK)
            .context("Enabling non-blocking reads")?;
        let tty = TtyGuard { file, original };
        let mut mode = tty.original.clone();
        if echo {
            mode.local_modes.insert(LocalModes::ECHO);
        } else {
            mode.local_modes
                .remove(LocalModes::ECHO | LocalModes::ECHONL);
        }
        // Keep canonical editing and ISIG: Ctrl+C cancels the async operation safely.
        mode.local_modes
            .insert(LocalModes::ICANON | LocalModes::ISIG);
        tcsetattr(&tty.file, OptionalActions::Now, &mode).context("Configuring terminal input")?;
        eprint!("{label}");
        std::io::stderr().flush()?;
        // Room for the limit plus one full read, so the buffer never reallocates
        // and leaves an unzeroized copy of the secret behind.
        let mut input = Zeroizing::new(Vec::with_capacity(MAX_INPUT + CHUNK));
        loop {
            let mut bytes = Zeroizing::new([0u8; CHUNK]);
            match (&tty.file).read(&mut bytes[..]) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // Only while awaiting local keyboard input. This never calls any network API.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
                Ok(0) => bail!("Input was cancelled"),
                Ok(count) => {
                    input.extend_from_slice(&bytes[..count]);
                    if input.len() > MAX_INPUT {
                        bail!("The input is too long");
                    }
                    if input.ends_with(b"\n") {
                        if !echo {
                            // The terminal did not echo the newline.
                            eprintln!();
                        }
                        let text =
                            std::str::from_utf8(&input).context("The input must be UTF-8")?;
                        return Ok(Zeroizing::new(
                            text.trim_end_matches(['\r', '\n']).to_owned(),
                        ));
                    }
                }
            }
        }
    }
}
#[cfg(unix)]
pub use unix::{confirm, hidden};
#[cfg(not(unix))]
pub async fn hidden(_label: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    anyhow::bail!("Hidden code input supports macOS/Linux only; Windows is not implemented")
}
#[cfg(not(unix))]
pub async fn confirm(_label: &str) -> bool {
    false
}

#[cfg_attr(not(unix), allow(dead_code))]
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_yes_confirms() {
        assert!(is_yes("y"));
        assert!(is_yes(" YES \r"));
        assert!(!is_yes(""));
        assert!(!is_yes("n"));
        assert!(!is_yes("yep"));
    }
}
