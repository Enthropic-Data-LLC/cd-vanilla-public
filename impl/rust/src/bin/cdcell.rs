// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! `cdcell` — a command-line opener, sealer and verifier for `.cell` files.
//!
//! ```text
//! cdcell keygen  --label Alice --out alice
//! cdcell seal    report.pdf --to alice.cdpub --out report.cell
//! cdcell verify  report.cell
//! cdcell inspect report.cell
//! cdcell open    report.cell --key alice.cdkey --out ./
//! ```
//!
//! `verify` and `inspect` need no key material at all: that a third party can
//! confirm a cell has not been altered, and see exactly what it does and does
//! not leak, without being able to read it, is the property the format rests on.

use cellular_defense::canonical::canonicalize;
use cellular_defense::cell::{create, open, verify, CreateOptions, OpenOptions, Recipient};
use cellular_defense::crypto;
use cellular_defense::keys::KeyRecord;
use cellular_defense::lifetime;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    let (command, rest) = args.split_first().unwrap();
    let result = match command.as_str() {
        "keygen" => cmd_keygen(rest),
        "seal" => cmd_seal(rest),
        "verify" => cmd_verify(rest),
        "inspect" => cmd_inspect(rest),
        "open" => cmd_open(rest),
        "-h" | "--help" | "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command {other:?}\n");
            usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", shown(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprint!(
        "cdcell — seal, open and verify .cell documents\n\
         \n  cdcell keygen  --label NAME --out STEM        generate a P-256 keypair\
         \n  cdcell seal    FILE --to PUB [--to PUB]...    encrypt into a .cell\
         \n  cdcell verify  CELL                          check the audit chain (no key needed)\
         \n  cdcell inspect CELL                          show what an observer can see\
         \n  cdcell open    CELL --key KEY --out PATH     decrypt\n"
    );
}

// ─── argument handling ──────────────────────────────────────────────────────

/// A deliberately small parser: flags may appear before or after positionals,
/// because users write the filename first and every other tool lets them.
struct Args {
    positional: Vec<String>,
    flags: HashMap<String, Vec<String>>,
    switches: Vec<String>,
}

impl Args {
    fn parse(args: &[String], valued: &[&str]) -> Result<Self, String> {
        let mut out = Args {
            positional: Vec::new(),
            flags: HashMap::new(),
            switches: Vec::new(),
        };
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if let Some(name) = arg.strip_prefix("--") {
                let (name, inline) = match name.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (name, None),
                };
                if valued.contains(&name) {
                    let value = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            args.get(i)
                                .cloned()
                                .ok_or_else(|| format!("--{name} needs a value"))?
                        }
                    };
                    out.flags.entry(name.to_string()).or_default().push(value);
                } else {
                    out.switches.push(name.to_string());
                }
            } else {
                out.positional.push(arg.clone());
            }
            i += 1;
        }
        Ok(out)
    }

    fn one(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|v| v.first()).map(|s| s.as_str())
    }
    fn many(&self, name: &str) -> &[String] {
        self.flags.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }
    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
}

type CmdResult = Result<(), Box<dyn std::error::Error>>;

// ─── keygen ─────────────────────────────────────────────────────────────────

fn cmd_keygen(args: &[String]) -> CmdResult {
    let args = Args::parse(args, &["label", "out"])?;
    let out = args.one("out").ok_or("--out is required")?;
    let key = KeyRecord::generate(args.one("label").unwrap_or("My Key"));

    let pub_path = format!("{out}.cdpub");
    let key_path = format!("{out}.cdkey");
    write_json(Path::new(&pub_path), &key.to_cdpub()?, 0o644)?;
    write_json(Path::new(&key_path), &key.to_cdkey()?, 0o600)?;

    println!("fingerprint  {}", key.fingerprint()?);
    println!("public key   {pub_path}   (share this — it is how others encrypt to you)");
    println!("private key  {key_path}   (never share; there is no recovery)");
    Ok(())
}

// ─── seal ───────────────────────────────────────────────────────────────────

fn cmd_seal(args: &[String]) -> CmdResult {
    let args = Args::parse(args, &["to", "threshold", "sign", "meta", "out"])?;
    let source = args
        .positional
        .first()
        .ok_or("usage: cdcell seal FILE --to RECIPIENT.cdpub")?;

    let mut recipients = Vec::new();
    for path in args.many("to") {
        let record = KeyRecord::from_cdpub(&read_json(Path::new(path))?)?;
        recipients.push(Recipient::for_key(&record)?);
    }
    if args.has("passphrase") {
        let entered = prompt_passphrase("Passphrase for this cell: ")?;
        if entered != prompt_passphrase("Repeat: ")? {
            return Err("passphrases do not match".into());
        }
        recipients.push(Recipient::argon2id(&entered, "")); // v1.4 default; pbkdf2 only for pre-1.4 cells
    }
    if recipients.is_empty() {
        return Err("a cell needs at least one recipient (--to or --passphrase)".into());
    }

    let data = std::fs::read(source)?;
    let mut opts = CreateOptions {
        content_type: Some(content_type_for(source)),
        threshold: args
            .one("threshold")
            .map(|t| t.parse::<usize>())
            .transpose()?
            .unwrap_or(1),
        ..Default::default()
    };
    if let Some(meta) = args.one("meta") {
        opts.meta = Some(serde_json::from_str(meta).map_err(|e| format!("--meta: {e}"))?);
    }
    if let Some(sign) = args.one("sign") {
        opts.sender = Some(KeyRecord::from_cdkey(&read_json(Path::new(sign))?)?);
    }

    let filename = Path::new(source)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| source.clone());
    let sealed = create(&data, &filename, &recipients, &opts)?;

    let destination = args
        .one("out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{source}.cell")));
    write_cell(&destination, &sealed)?;

    let header = &sealed["header"];
    let count = header["access_map"].as_array().map(|a| a.len()).unwrap_or(0);
    println!(
        "sealed {}  ({count} recipient{}, {}-of-{})",
        destination.display(),
        if count == 1 { "" } else { "s" },
        header["threshold"]["required"],
        header["threshold"]["of_total"]
    );
    Ok(())
}

// ─── verify ─────────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) -> CmdResult {
    let args = Args::parse(args, &["expect-signer"])?;
    let path = args.positional.first().ok_or("usage: cdcell verify CELL")?;
    let cell = read_cell(Path::new(path))?;
    let result = verify(&cell, args.one("expect-signer"))?;

    println!("version        {}", result.version);
    println!("header_hash    ok");
    println!(
        "payload_hash   {}",
        if result.payload_hash_ok { "ok" } else { "absent" }
    );
    if result.signed {
        println!(
            "signature      valid, by key {}",
            result.signer_fingerprint.as_deref().unwrap_or("(unknown)")
        );
        println!(
            "               (claims to be {:?} — self-asserted, check the fingerprint",
            result.claimed_signer.as_deref().unwrap_or("")
        );
        println!("               against a contact you already trust)");
    } else {
        println!("signature      none present");
        println!("               a signature can be stripped undetectably; absence proves nothing");
    }
    Ok(())
}

// ─── inspect ────────────────────────────────────────────────────────────────

fn cmd_inspect(args: &[String]) -> CmdResult {
    let args = Args::parse(args, &[])?;
    let path = args.positional.first().ok_or("usage: cdcell inspect CELL")?;
    let cell = read_cell(Path::new(path))?;
    let header = &cell["header"];

    let version = cell
        .get("version")
        .or_else(|| cell.get("cd_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    // Every value here can be edited by anyone who handled the file.
    println!("version      {}", shown(version));
    println!("doc_id       {}", shown(cell["doc_id"].as_str().unwrap_or("")));
    println!("created_at   {}", shown(&cell["created_at"].to_string()));
    println!(
        "threshold    {}-of-{}",
        shown(&header["threshold"]["required"].to_string()),
        shown(&header["threshold"]["of_total"].to_string())
    );

    if let Some(lt) = lifetime::read(header.get("lifetime")) {
        println!("lifetime     type={}", shown(&lt.type_));
        println!(
            "  advisory   retain_until={:?} release_at={:?} single_use={} minimum_atl={}",
            lt.retain_until, lt.release_at, lt.single_use, lt.minimum_atl
        );
        println!("             (advisory: honoured by conforming software, NOT enforced against a keyholder)");
        println!(
            "  disposal   at={:?} action={}",
            lt.disposal_at,
            shown(&lt.disposal_action)
        );
        println!("             (enforced by whoever stores the ciphertext)");
    }

    println!("access_map:");
    let entries = header
        .get("access_map")
        .or_else(|| cell.get("recipients"))
        .and_then(|v| v.as_array());
    for entry in entries.into_iter().flatten() {
        let share = entry
            .get("share_index")
            .map(|i| format!("  share {}", shown(&i.to_string())))
            .unwrap_or_default();
        println!(
            "  - {:<12} {}  {}{share}",
            shown(entry["method"].as_str().unwrap_or("")),
            shown(entry["fingerprint"].as_str().unwrap_or("")),
            shown(&format!("{:?}", entry["label"].as_str().unwrap_or("")))
        );
    }

    if let Some(payload) = cell.get("payload").or_else(|| cell.get("encrypted_body")) {
        if let Some(ct) = payload
            .get("ciphertext")
            .or_else(|| payload.get("ct"))
            .and_then(|v| v.as_str())
        {
            if let Ok(bytes) = crypto::decode_b64(ct, "ciphertext") {
                println!(
                    "ciphertext   {} bytes ({})",
                    bytes.len(),
                    shown(payload["alg"].as_str().unwrap_or(""))
                );
            }
        }
    }
    println!("\nnot visible here: the plaintext, the filename, the media type, the original");
    println!("size, and any sender-defined meta — all of them live inside the ciphertext (§5).");
    Ok(())
}

// ─── open ───────────────────────────────────────────────────────────────────

fn cmd_open(args: &[String]) -> CmdResult {
    let args = Args::parse(args, &["key", "expect-signer", "out"])?;
    let path = args
        .positional
        .first()
        .ok_or("usage: cdcell open CELL --key KEY.cdkey")?;
    let cell = read_cell(Path::new(path))?;

    let mut opts = OpenOptions {
        expected_signer: args.one("expect-signer").map(str::to_string),
        ignore_advisory: args.has("ignore-advisory"),
        ..Default::default()
    };
    for key_path in args.many("key") {
        opts.keys
            .push(KeyRecord::from_cdkey(&read_json(Path::new(key_path))?)?);
    }
    if args.has("passphrase") {
        opts.passphrases.push(prompt_passphrase("Passphrase: ")?);
    }

    let result = open(&cell, &opts)?;

    // A trailing separator means "into this directory" even if it does not
    // exist yet; the filename is only known once the manifest is decrypted (§5),
    // so the caller cannot always name the output file in advance.
    let out = args.one("out").unwrap_or(".");
    let mut destination = PathBuf::from(out);
    if destination.is_dir() || out.ends_with('/') {
        std::fs::create_dir_all(&destination)?;
        destination.push(safe_filename(&result.filename));
    }
    write_new(&destination, &result.data)?;

    // Who signed comes first, before any text the sender chose.
    if result.signed {
        println!(
            "signed by key {}",
            result.signer_fingerprint.as_deref().unwrap_or("(unknown)")
        );
    } else {
        println!("not signed     nothing in this cell says who sent it");
    }
    println!(
        "wrote {}  ({} bytes, {})",
        shown(&destination.display().to_string()),
        result.data.len(),
        shown(&result.content_type)
    );
    if let Some(meta) = &result.meta {
        println!("sender meta: {}", shown(&canonicalize(meta)?));
    }
    Ok(())
}

// ── Sender-chosen text ──────────────────────────────────────────────────────
// The filename, media type and meta come from whoever sealed the cell, and
// inspect's header fields from anyone who handled it. None of it may reach the
// filesystem or the terminal as is: a newline or ESC can print a fake
// "signed by key" line, bidi controls can reverse what a name appears to say.

/// C0/C1 controls, bidi and zero-width format characters, line and paragraph
/// separators. The same set in every port's CLI.
fn unsafe_char(c: char) -> bool {
    let o = c as u32;
    o < 0x20
        || (0x7f..=0x9f).contains(&o)
        || o == 0x061c
        || (0x200b..=0x200f).contains(&o)
        || (0x2028..=0x202e).contains(&o)
        || (0x2060..=0x2069).contains(&o)
        || o == 0xfeff
}

/// Text safe to print: every unsafe character as a visible `\uXXXX` escape.
fn shown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if unsafe_char(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The sender's filename as a plain name in the output directory: no path,
/// no unsafe characters, no leading dot (no .bashrc, .envrc), at most 200 bytes.
fn safe_filename(name: &str) -> String {
    let base = name.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("");
    let base: String = base.chars().filter(|&c| !unsafe_char(c)).collect();
    let base = base.trim_start_matches(|c: char| c == '.' || c.is_whitespace());
    let mut cut = base.len().min(200);
    while !base.is_char_boundary(cut) {
        cut -= 1;
    }
    let base = base[..cut].trim_end();
    if base.is_empty() {
        "decrypted".into()
    } else {
        base.to_string()
    }
}

/// Create the file; never overwrite it or follow a symlink. Owner-only: it is
/// the plaintext of an encrypted file.
fn write_new(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "{} already exists — not overwriting it; name a new file with --out",
                path.display()
            )
            .into())
        }
        other => other?,
    };
    file.write_all(data)?;
    Ok(())
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn write_json(path: &Path, value: &Value, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text)?;
    set_mode(path, mode)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Read a `.cell` or a gzip-compressed `.celz` (spec §3).
fn read_cell(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    if raw.len() > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&raw[..])
            .take(cellular_defense::crypto::MAX_DECOMPRESSED)
            .read_to_end(&mut decoded)?;
        return Ok(serde_json::from_slice(&decoded)?);
    }
    Ok(serde_json::from_slice(&raw)?)
}

fn write_cell(path: &Path, cell: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut text = serde_json::to_string_pretty(cell)?;
    text.push('\n');
    if path.extension().map(|e| e == "celz").unwrap_or(false) {
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text.as_bytes())?;
        std::fs::write(path, encoder.finish()?)?;
    } else {
        std::fs::write(path, text)?;
    }
    Ok(())
}

fn content_type_for(path: &str) -> String {
    // A deliberately tiny table rather than a mime crate: the value is a hint
    // carried inside the ciphertext, not something the format acts on.
    let ext = Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "html" => "text/html",
        "csv" => "text/csv",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Prompt for a passphrase, suppressing echo via `stty` when on a terminal.
///
/// Deliberately no dependency: this crate is meant to be embedded, and adding
/// one to the manifest purely so a CLI can hide a passphrase puts it in every
/// consumer's dependency graph.
fn prompt_passphrase(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{prompt}");
    let hide = std::process::Command::new("stty")
        .args(["-F", "/dev/tty", "-echo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;

    if hide {
        let _ = std::process::Command::new("stty")
            .args(["-F", "/dev/tty", "echo"])
            .status();
        eprintln!();
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sender-chosen filename and text (pen test 2026-11-09, M1/M2).

    #[test]
    fn safe_filename_cases() {
        let long = "\u{e9}".repeat(150);
        let cut = "\u{e9}".repeat(100);
        for (raw, want) in [
            ("report.pdf", "report.pdf"),
            ("../../etc/passwd", "passwd"),
            ("a\\b\\c.txt", "c.txt"),
            (".bashrc", "bashrc"),
            (". .envrc", "envrc"),
            ("..", "decrypted"),
            ("/", "decrypted"),
            ("", "decrypted"),
            ("x\u{0}y\nz", "xyz"),
            ("contract\u{202e}fdp.exe", "contractfdp.exe"),
            (long.as_str(), cut.as_str()),
        ] {
            assert_eq!(safe_filename(raw), want, "{raw:?}");
        }
    }

    #[test]
    fn shown_escapes_what_could_forge_a_line() {
        let got = shown("application/pdf\nsigned by key aff6a52990ce2335\u{1b}[8m\u{202e}");
        assert!(!got.contains(['\n', '\u{1b}', '\u{202e}']), "{got:?}");
        for esc in ["\\u000a", "\\u001b", "\\u202e"] {
            assert!(got.contains(esc), "{got:?} lacks {esc}");
        }
    }

    #[test]
    fn write_new_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("cdcell-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mine = dir.join(".bashrc");
        std::fs::write(&mine, b"mine").unwrap();
        assert!(write_new(&mine, b"attacker").is_err());
        assert_eq!(std::fs::read(&mine).unwrap(), b"mine");
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(dir.join("elsewhere"), &link).unwrap();
            assert!(write_new(&link, b"attacker").is_err(), "followed a dangling symlink");
            assert!(!dir.join("elsewhere").exists());
        }
        let fresh = dir.join("fresh");
        write_new(&fresh, b"ok").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
