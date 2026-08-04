//! The long-running filter: one process for a whole git operation.
//!
//! Registering `filter.git-xcrypt.process` rather than `clean`/`smudge` is not
//! an optimisation. With the catch-all attribute git hands us every file in the
//! repository, and a process per file measured 12 105 ms against 596 ms for one
//! long-running process on the same 2000 files.
//!
//! Everything the protocol says goes over `stdout`, which makes the rule from
//! AGENTS.md absolute here: no `println!` anywhere beneath this module.

use std::io::{Read, Write};

use bstr::ByteSlice as _;

use crate::config::Config;
use crate::decide;
use crate::key::MasterKey;
use crate::pktline::{self, Packet};
use crate::repo::Repo;
use crate::{Error, Result};

/// What the repository can tell the filter, resolved once per process.
///
/// Loading this once is the point of the long-running protocol: the
/// configuration and the key are read on startup, not per file.
pub struct Context {
    config: Config,
    /// Where `config` came from, so an absent one can be looked for again.
    config_path: std::path::PathBuf,
    key: Option<MasterKey>,
    autocrlf: Option<String>,
    core_eol: Option<String>,
}

impl Context {
    /// Gathers everything the filter needs from `repo`.
    ///
    /// A missing key is not fatal here: a locked repository still has to check
    /// out its ciphertext and pass unselected files through.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when `.git-xcrypt` cannot be understood — that must
    /// stop the operation rather than silently encrypt nothing.
    pub fn load(repo: &Repo) -> Result<Self> {
        let config_path = repo.xcrypt_config_path();
        let config = Config::load(&config_path)?;
        for warning in &config.pointless_eol {
            eprintln!("git-xcrypt: {warning}");
        }

        let key = match repo.load_key() {
            Ok(key) => Some(key),
            Err(Error::NoKey) => None,
            Err(err) => return Err(err),
        };

        // Full precedence, not just `.git/config`: `core.autocrlf` lives in the
        // user's global file on nearly every machine that sets it at all.
        let git_config = crate::gitconfig::open_full(repo.git_dir())?;
        Ok(Self {
            config,
            config_path,
            key,
            autocrlf: crate::gitconfig::get(&git_config, "core.autocrlf"),
            core_eol: crate::gitconfig::get(&git_config, "core.eol"),
        })
    }

    /// Looks for `.git-xcrypt` again if it was absent when the process started.
    ///
    /// One process serves a whole git operation, and a `git checkout` that
    /// restores `.git-xcrypt` filters other files in the same run. Latching the
    /// absence would make the check-in refusal outlive its own cause and leave
    /// the repository unrepairable from inside git.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the file has reappeared but cannot be understood.
    fn refresh_config_if_absent(&mut self) -> Result<()> {
        if !self.config.missing {
            return Ok(());
        }

        let reloaded = Config::load(&self.config_path)?;
        if !reloaded.missing {
            for warning in &reloaded.pointless_eol {
                eprintln!("git-xcrypt: {warning}");
            }
            self.config = reloaded;
        }
        Ok(())
    }
}

/// Runs the protocol to completion on the given streams.
///
/// # Errors
///
/// [`Error::Io`] or [`Error::Format`] when the handshake itself fails. A failure
/// on a single file is reported to git as `status=error` instead, which with
/// `required = true` aborts the operation.
pub fn run(context: &mut Context, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    handshake(input, output)?;
    negotiate_capabilities(input, output)?;

    loop {
        let Some(request) = read_request(input)? else {
            return Ok(());
        };
        serve(context, &request, output)?;
    }
}

/// One `command=` / `pathname=` pair and the content that followed it.
struct Request {
    command: String,
    /// Kept as bytes: on Unix a path is an arbitrary byte string, and decoding
    /// it lossily would hand the decision a name the file does not have.
    pathname: Vec<u8>,
    content: Vec<u8>,
}

/// Agrees on the protocol version.
fn handshake(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let greeting = pktline::read_until_flush(input)?;
    let announces_version_2 = greeting
        .iter()
        .any(|item| item.as_slice() == b"version=2\n");
    if !announces_version_2 {
        return Err(Error::Format(
            "git asked for a filter protocol version this build does not speak".into(),
        ));
    }

    pktline::write_data(output, b"git-filter-server\n")?;
    pktline::write_data(output, b"version=2\n")?;
    pktline::write_flush(output)?;
    Ok(())
}

/// Tells git which operations we handle.
fn negotiate_capabilities(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let _offered = pktline::read_until_flush(input)?;
    pktline::write_data(output, b"capability=clean\n")?;
    pktline::write_data(output, b"capability=smudge\n")?;
    pktline::write_flush(output)?;
    Ok(())
}

/// Reads one request, or `None` when git closed the stream.
fn read_request(input: &mut impl Read) -> Result<Option<Request>> {
    let mut command = None;
    let mut pathname = None;

    loop {
        match pktline::read_packet(input) {
            Ok(Packet::Flush) => break,
            Ok(Packet::Data(payload)) => {
                // Exactly the one terminating newline comes off, never
                // `trim_end`: a filename may legally end in a space, and
                // trimming it matches the file under a different name — which
                // on the check-in side means storing a secret in the clear.
                let value = payload.strip_suffix(b"\n").unwrap_or(&payload);
                if let Some(rest) = value.strip_prefix(b"command=") {
                    command = Some(String::from_utf8_lossy(rest).into_owned());
                } else if let Some(rest) = value.strip_prefix(b"pathname=") {
                    pathname = Some(rest.to_vec());
                }
            }
            // git closes the stream when the operation is over, which arrives
            // as an unexpected end of file rather than as a message.
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
    }

    let (command, pathname) = match (command, pathname) {
        (Some(command), Some(pathname)) => (command, pathname),
        // Neither field is how a clean shutdown looks; one of the two is a
        // request we did not understand, and answering nothing while exiting
        // zero would tell git the file was handled.
        (None, None) => return Ok(None),
        (command, _) => {
            return Err(Error::Format(format!(
                "git sent an incomplete filter request (command={}, pathname missing or absent)",
                command.as_deref().unwrap_or("<none>")
            )));
        }
    };

    Ok(Some(Request {
        command,
        pathname,
        content: pktline::read_content(input)?,
    }))
}

/// Answers one request.
fn serve(context: &mut Context, request: &Request, output: &mut impl Write) -> Result<()> {
    let outcome = match request.command.as_str() {
        "clean" => context.refresh_config_if_absent().and_then(|()| {
            decide::clean(
                context.key.as_ref(),
                &context.config,
                &request.pathname,
                &request.content,
            )
        }),
        "smudge" => decide::smudge(
            context.key.as_ref(),
            &request.pathname,
            &request.content,
            context.config.decide(&request.pathname).eol,
            context.autocrlf.as_deref(),
            context.core_eol.as_deref(),
        ),
        other => Err(Error::Format(format!(
            "git asked for the unknown filter command `{other}`"
        ))),
    };

    match outcome {
        Ok(outcome) => {
            if let Some(warning) = outcome.warning {
                eprintln!("git-xcrypt: {warning}");
            }
            pktline::write_data(output, b"status=success\n")?;
            pktline::write_flush(output)?;
            pktline::write_data(output, &outcome.content)?;
            pktline::write_flush(output)?;
            pktline::write_flush(output)?;
        }
        Err(err) => {
            // With `required = true` this aborts the whole git operation, which
            // is the point: better a refused commit than a leaked secret.
            eprintln!("git-xcrypt: {}: {err}", request.pathname.as_bstr());
            pktline::write_data(output, b"status=error\n")?;
            pktline::write_flush(output)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;
    use crate::pktline::{write_data, write_flush};

    fn context() -> Context {
        Context {
            config: Config::parse("*.env\n").expect("test config"),
            config_path: std::path::PathBuf::from(".git-xcrypt"),
            key: Some(MasterKey::from_bytes([11u8; MASTER_KEY_LEN])),
            autocrlf: None,
            core_eol: None,
        }
    }

    /// Builds the byte stream git would send for one request.
    fn conversation(command: &str, pathname: &str, content: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"git-filter-client\n").expect("writing");
        write_data(&mut buffer, b"version=2\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, b"capability=clean\n").expect("writing");
        write_data(&mut buffer, b"capability=smudge\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, format!("command={command}\n").as_bytes()).expect("writing");
        write_data(&mut buffer, format!("pathname={pathname}\n").as_bytes()).expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, content).expect("writing");
        write_flush(&mut buffer).expect("writing");
        buffer
    }

    /// Pulls the payload of the reply that follows `status=success`.
    fn reply_content(reply: &[u8]) -> Vec<u8> {
        let mut cursor = reply;
        // server greeting, capabilities, then the status list.
        pktline::read_until_flush(&mut cursor).expect("greeting");
        pktline::read_until_flush(&mut cursor).expect("capabilities");
        let status = pktline::read_until_flush(&mut cursor).expect("status");
        assert_eq!(
            status[0], b"status=success\n",
            "the filter reported a failure"
        );
        pktline::read_content(&mut cursor).expect("content")
    }

    #[test]
    fn a_clean_request_comes_back_encrypted() {
        let mut reply = Vec::new();
        let input = conversation("clean", "a.env", b"api_key = secret\n");
        run(&mut context(), &mut input.as_slice(), &mut reply).expect("the protocol must complete");

        let content = reply_content(&reply);
        assert!(crate::format::looks_encrypted(&content));
    }

    #[test]
    fn an_unselected_path_comes_back_untouched() {
        let mut reply = Vec::new();
        let input = conversation("clean", "README.md", b"public\n");
        run(&mut context(), &mut input.as_slice(), &mut reply).expect("the protocol must complete");
        assert_eq!(reply_content(&reply), b"public\n");
    }

    #[test]
    fn a_smudge_request_comes_back_decrypted() {
        let mut context = context();
        let stored =
            crate::crypto::encrypt(context.key.as_ref().expect("key"), 0, b"api_key = secret\n")
                .expect("encryption");

        let mut reply = Vec::new();
        let input = conversation("smudge", "a.env", &stored);
        run(&mut context, &mut input.as_slice(), &mut reply).expect("the protocol must complete");
        assert_eq!(reply_content(&reply), b"api_key = secret\n");
    }

    #[test]
    fn a_wrong_protocol_version_is_refused_before_any_file_is_touched() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"git-filter-client\n").expect("writing");
        write_data(&mut buffer, b"version=99\n").expect("writing");
        write_flush(&mut buffer).expect("writing");

        let mut reply = Vec::new();
        assert!(run(&mut context(), &mut buffer.as_slice(), &mut reply).is_err());
    }

    #[test]
    fn a_failing_file_is_reported_as_an_error_not_as_content() {
        // A locked repository: the path is selected but no key is loaded.
        let mut context = Context {
            config: Config::parse("*.env\n").expect("test config"),
            config_path: std::path::PathBuf::from(".git-xcrypt"),
            key: None,
            autocrlf: None,
            core_eol: None,
        };

        let mut reply = Vec::new();
        let input = conversation("clean", "a.env", b"api_key = secret\n");
        run(&mut context, &mut input.as_slice(), &mut reply).expect("the protocol must complete");

        let mut cursor = reply.as_slice();
        pktline::read_until_flush(&mut cursor).expect("greeting");
        pktline::read_until_flush(&mut cursor).expect("capabilities");
        let status = pktline::read_until_flush(&mut cursor).expect("status");
        assert_eq!(status[0], b"status=error\n");
        assert!(
            !reply.windows(9).any(|w| w == b"api_key ="),
            "the plaintext must not appear in the reply"
        );
    }

    #[test]
    fn one_process_serves_several_files() {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"git-filter-client\n").expect("writing");
        write_data(&mut buffer, b"version=2\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, b"capability=clean\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        for name in ["a.env", "b.env", "c.env"] {
            write_data(&mut buffer, b"command=clean\n").expect("writing");
            write_data(&mut buffer, format!("pathname={name}\n").as_bytes()).expect("writing");
            write_flush(&mut buffer).expect("writing");
            write_data(&mut buffer, b"secret\n").expect("writing");
            write_flush(&mut buffer).expect("writing");
        }

        let mut reply = Vec::new();
        run(&mut context(), &mut buffer.as_slice(), &mut reply)
            .expect("the protocol must complete");

        let mut cursor = reply.as_slice();
        pktline::read_until_flush(&mut cursor).expect("greeting");
        pktline::read_until_flush(&mut cursor).expect("capabilities");
        for _ in 0..3 {
            let status = pktline::read_until_flush(&mut cursor).expect("status");
            assert_eq!(status[0], b"status=success\n");
            let content = pktline::read_content(&mut cursor).expect("content");
            assert!(crate::format::looks_encrypted(&content));
            pktline::read_until_flush(&mut cursor).expect("trailing flush");
        }
    }
}
