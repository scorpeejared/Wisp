//! `wisp-admin` — the owner's tool for running the guest list.
//!
//! Operates directly on the relay's SQLite file. There is no admin API and no
//! admin credential to steal: the only way in is filesystem access to the
//! database, which the machine owner already has and nobody else should.
//!
//! ```text
//! wisp-admin new --expires-in 7d --note "for bob"
//! wisp-admin list
//! wisp-admin revoke WISP-A1B2-C3D4-E5F6-G7H8
//! wisp-admin accounts
//! wisp-admin lock <public-key-hex> --for 24h
//! wisp-admin unlock <public-key-hex>
//! ```
//!
//! Argument parsing is hand-rolled rather than pulled from a crate: six
//! subcommands do not justify a dependency in a project whose stated principle
//! is that no feature or package ships unless it must.

use std::process::ExitCode;

use wisp_invite::{InviteCode, RedemptionHash};
use wisp_server::{now, PublicKey, Store};

const DEFAULT_DB: &str = "wisp.db";
const USAGE: &str = "\
wisp-admin — Wisp invite and account management

USAGE:
    wisp-admin [--db <path>] <command> [options]

COMMANDS:
    new         Issue a single-use invite code
    list        Show all invite codes and their status
    revoke      Revoke an unused invite code
    accounts    List registered accounts
    lock        Refuse relay service for an account
    unlock      Restore relay service for an account

OPTIONS:
    --db <path>          Relay database (default: wisp.db, or $WISP_DB)

  new:
    --expires-in <dur>   Validity window (default: 7d)
    --note <text>        Reminder of who this was for; never leaves the server

  lock:
    --for <dur>          How long to lock (default: 24h)

Durations are like 30m, 24h, 7d.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }

    let (db_path, rest) = extract_option(args, "--db");
    let db_path = db_path
        .or_else(|| std::env::var("WISP_DB").ok())
        .unwrap_or_else(|| DEFAULT_DB.to_string());

    let command = rest.first().ok_or("no command given")?.clone();
    let rest = &rest[1..];

    let store = Store::open(&db_path).map_err(|e| format!("opening {db_path}: {e}"))?;

    match command.as_str() {
        "new" => cmd_new(&store, rest),
        "list" => cmd_list(&store),
        "revoke" => cmd_revoke(&store, rest),
        "accounts" => cmd_accounts(&store),
        "lock" => cmd_lock(&store, rest),
        "unlock" => cmd_unlock(&store, rest),
        other => Err(format!("unknown command {other:?}; try --help")),
    }
}

fn cmd_new(store: &Store, args: &[String]) -> Result<(), String> {
    let (expires_in, args) = extract_option(args, "--expires-in");
    let (note, _) = extract_option(&args, "--note");

    let window = parse_duration(expires_in.as_deref().unwrap_or("7d"))?;
    let code = InviteCode::generate();

    store
        .create_invite(&code.redemption_hash(), now() + window, note.as_deref())
        .map_err(|e| format!("storing invite: {e}"))?;

    // The code exists in plaintext exactly here and nowhere else. The database
    // holds only its hash, so this output cannot be recovered afterwards.
    println!();
    println!("  {code}");
    println!();
    println!("  Expires in {}", describe_duration(window));
    if let Some(note) = note {
        println!("  Note: {note}");
    }
    println!();
    println!("  This code is shown once and is not recoverable. Copy it now.");
    println!("  Anyone holding it can create an account — send it privately.");
    println!();
    Ok(())
}

fn cmd_list(store: &Store) -> Result<(), String> {
    let invites = store.list_invites().map_err(|e| e.to_string())?;
    if invites.is_empty() {
        println!("No invite codes issued.");
        return Ok(());
    }

    println!(
        "{:<18}  {:<10}  {:<20}  {}",
        "CODE (hash)", "STATUS", "EXPIRES", "NOTE"
    );
    for (hash, record) in invites {
        let status = if record.used_at.is_some() {
            "used"
        } else if record.revoked_at.is_some() {
            "revoked"
        } else if record.expires_at <= now() {
            "expired"
        } else {
            "open"
        };
        println!(
            "{:<18}  {:<10}  {:<20}  {}",
            &hash.to_hex()[..16],
            status,
            describe_deadline(record.expires_at),
            record.note.unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_revoke(store: &Store, args: &[String]) -> Result<(), String> {
    let target = args.first().ok_or("usage: wisp-admin revoke <code|hash>")?;
    let hash = resolve_invite(store, target)?;

    if store.revoke_invite(&hash).map_err(|e| e.to_string())? {
        println!("Revoked.");
        Ok(())
    } else {
        Err("that invite is already used, revoked, or unknown".into())
    }
}

fn cmd_accounts(store: &Store) -> Result<(), String> {
    let accounts = store.list_accounts().map_err(|e| e.to_string())?;
    if accounts.is_empty() {
        println!("No accounts registered.");
        return Ok(());
    }

    println!("{:<66}  {:<12}  {}", "PUBLIC KEY", "REGISTERED", "STATUS");
    for (key, created_at, locked_until) in accounts {
        let status = match locked_until {
            Some(until) if until > now() => format!("locked {}", describe_deadline(until)),
            _ => "active".to_string(),
        };
        println!(
            "{:<66}  {:<12}  {}",
            hex(&key),
            describe_deadline(created_at),
            status
        );
    }
    // Usernames are stored only as hashes, so there is nothing to show here.
    println!();
    println!("Usernames are stored hashed and cannot be listed.");
    Ok(())
}

fn cmd_lock(store: &Store, args: &[String]) -> Result<(), String> {
    let (window, args) = extract_option(args, "--for");
    let key = parse_public_key(args.first().ok_or("usage: wisp-admin lock <public-key>")?)?;
    let window = parse_duration(window.as_deref().unwrap_or("24h"))?;

    store
        .lock_account(&key, now() + window)
        .map_err(|e| e.to_string())?;
    println!("Locked for {}.", describe_duration(window));
    Ok(())
}

fn cmd_unlock(store: &Store, args: &[String]) -> Result<(), String> {
    let key = parse_public_key(args.first().ok_or("usage: wisp-admin unlock <public-key>")?)?;
    store.lock_account(&key, 0).map_err(|e| e.to_string())?;
    println!("Unlocked.");
    Ok(())
}

/// Accepts either a full invite code or a hex hash prefix.
///
/// The code is the useful form when revoking something just issued; the hash
/// prefix is what `list` prints, since the code itself is unrecoverable.
fn resolve_invite(store: &Store, target: &str) -> Result<RedemptionHash, String> {
    if let Ok(code) = InviteCode::parse(target) {
        return Ok(code.redemption_hash());
    }

    let candidates: Vec<_> = store
        .list_invites()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|(hash, _)| hash.to_hex().starts_with(&target.to_lowercase()))
        .collect();

    match candidates.len() {
        0 => Err(format!("no invite matches {target:?}")),
        1 => Ok(candidates[0].0),
        n => Err(format!("{target:?} matches {n} invites; give more characters")),
    }
}

fn parse_public_key(text: &str) -> Result<PublicKey, String> {
    let text = text.trim();
    if text.len() != 64 {
        return Err("public key must be 64 hex characters".into());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "public key must be hex".to_string())?;
    }
    Ok(key)
}

/// Pulls `--name value` out of the argument list, returning it and the rest.
fn extract_option(args: &[String], name: &str) -> (Option<String>, Vec<String>) {
    let mut value = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if args[i] == name && i + 1 < args.len() {
            value = Some(args[i + 1].clone());
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (value, rest)
}

fn parse_duration(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("{text:?} needs a unit, like 7d"))?,
    );
    let amount: i64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a duration"))?;
    if amount <= 0 {
        return Err("duration must be positive".into());
    }

    let seconds = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => return Err(format!("unknown unit {other:?}; use m, h, or d")),
    };
    Ok(amount * seconds)
}

fn describe_duration(seconds: i64) -> String {
    match seconds {
        s if s % 86_400 == 0 => format!("{} day(s)", s / 86_400),
        s if s % 3600 == 0 => format!("{} hour(s)", s / 3600),
        s => format!("{} minute(s)", s / 60),
    }
}

/// Renders an absolute timestamp as a relative one, so the output is readable
/// without a date library.
fn describe_deadline(timestamp: i64) -> String {
    let delta = timestamp - now();
    let magnitude = delta.abs();
    let rendered = match magnitude {
        s if s < 60 => "moments".to_string(),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    };
    if delta >= 0 {
        format!("in {rendered}")
    } else {
        format!("{rendered} ago")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("24h").unwrap(), 86_400);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
    }

    #[test]
    fn bad_durations_are_rejected() {
        for bad in ["", "7", "d", "7y", "-1d", "0d", "abc"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn options_are_extracted_without_disturbing_the_rest() {
        let args: Vec<String> = ["new", "--note", "for bob", "extra"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (note, rest) = extract_option(&args, "--note");
        assert_eq!(note.as_deref(), Some("for bob"));
        assert_eq!(rest, vec!["new".to_string(), "extra".to_string()]);
    }

    #[test]
    fn a_missing_option_leaves_arguments_alone() {
        let args: Vec<String> = ["list"].iter().map(|s| s.to_string()).collect();
        let (value, rest) = extract_option(&args, "--db");
        assert!(value.is_none());
        assert_eq!(rest, args);
    }

    /// A dangling flag with no value must not swallow the command.
    #[test]
    fn a_trailing_flag_without_a_value_is_kept() {
        let args: Vec<String> = ["list", "--db"].iter().map(|s| s.to_string()).collect();
        let (value, rest) = extract_option(&args, "--db");
        assert!(value.is_none());
        assert_eq!(rest, args);
    }

    #[test]
    fn public_keys_parse_from_hex() {
        let key = parse_public_key(&"ab".repeat(32)).unwrap();
        assert_eq!(key, [0xAB; 32]);
    }

    #[test]
    fn bad_public_keys_are_rejected() {
        assert!(parse_public_key("abc").is_err());
        assert!(parse_public_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn issuing_and_revoking_round_trips() {
        let store = Store::in_memory().unwrap();
        let code = InviteCode::generate();
        store
            .create_invite(&code.redemption_hash(), now() + 3600, Some("bob"))
            .unwrap();

        // Resolvable by full code and by hash prefix.
        assert_eq!(
            resolve_invite(&store, &code.to_string()).unwrap(),
            code.redemption_hash()
        );
        let prefix = &code.redemption_hash().to_hex()[..16];
        assert_eq!(
            resolve_invite(&store, prefix).unwrap(),
            code.redemption_hash()
        );

        assert!(store.revoke_invite(&code.redemption_hash()).unwrap());
        assert!(!store.revoke_invite(&code.redemption_hash()).unwrap());
    }

    #[test]
    fn resolving_an_unknown_invite_fails() {
        let store = Store::in_memory().unwrap();
        assert!(resolve_invite(&store, "deadbeef").is_err());
    }

    #[test]
    fn deadlines_read_naturally() {
        assert!(describe_deadline(now() + 7200).starts_with("in 2h"));
        assert!(describe_deadline(now() - 7200).ends_with("ago"));
    }
}
