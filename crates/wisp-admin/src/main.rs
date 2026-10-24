use std::process::ExitCode;

use wisp_server::{now, PublicKey, Store};

const DEFAULT_DB: &str = "wisp.db";
const USAGE: &str = "\
wisp-admin — Wisp account moderation

USAGE:
    wisp-admin [--db <path>] <command> [options]

COMMANDS:
    accounts    List registered accounts
    lock        Refuse relay service for an account
    unlock      Restore relay service for an account

OPTIONS:
    --db <path>          Relay database (default: wisp.db, or $WISP_DB)

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
        "accounts" => cmd_accounts(&store),
        "lock" => cmd_lock(&store, rest),
        "unlock" => cmd_unlock(&store, rest),
        other => Err(format!("unknown command {other:?}; try --help")),
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
        let args: Vec<String> = ["lock", "--for", "2h", "extra"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (window, rest) = extract_option(&args, "--for");
        assert_eq!(window.as_deref(), Some("2h"));
        assert_eq!(rest, vec!["lock".to_string(), "extra".to_string()]);
    }

    #[test]
    fn a_missing_option_leaves_arguments_alone() {
        let args: Vec<String> = ["list"].iter().map(|s| s.to_string()).collect();
        let (value, rest) = extract_option(&args, "--db");
        assert!(value.is_none());
        assert_eq!(rest, args);
    }

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
    fn deadlines_read_naturally() {
        assert!(describe_deadline(now() + 7200).starts_with("in 2h"));
        assert!(describe_deadline(now() - 7200).ends_with("ago"));
    }
}
