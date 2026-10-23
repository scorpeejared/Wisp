// Release builds must not open a console window behind the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Tauri shell.
//!
//! This layer is deliberately thin. It owns no security logic: it forwards
//! commands to [`wisp_session::Session`], which is the single authority on what
//! the user may see, and pushes status changes to the webview when the USB
//! watcher notices something.
//!
//! # What the webview is trusted with
//!
//! Nothing. The frontend renders whatever [`Status`] it is handed and can call
//! the commands below, but it cannot reach a key, a passphrase, or the
//! filesystem. No Tauri filesystem, shell, or HTTP plugin is enabled — see
//! `capabilities/default.json`. A compromised renderer can therefore ask to
//! unlock, exactly as a user can, and learns nothing it was not already shown.

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, Manager, State};
use zeroize::Zeroize;

use wisp_core::passphrase;
use wisp_session::{Session, Status};
use wisp_usb::watcher::{Watcher, DEFAULT_POLL_INTERVAL};

mod dev_drive;
mod messaging;
mod relay_client;

use dev_drive::AppVolumeProvider;
use messaging::{
    parse_identity, GroupMessageView, GroupView, MessageView, Messaging,
};
use relay_client::HttpRelayClient;

/// Brings messaging up after a successful unlock.
///
/// Deliberately best-effort: a relay that is down must not stop someone
/// unlocking and reading the history they already have. The UI learns the
/// connection state from the `wisp://connection` event rather than from this
/// returning.
fn start_messaging(app: &tauri::AppHandle, session: &AppSession, messaging: &Messaging) {
    let Some(public_key) = session.public_key() else {
        return;
    };

    // One short-lived copy of the private key, wiped below. The messaging
    // store needs its own; there is no way to share the session's.
    let Some(mut private_key) = session.with_identity(|identity| {
        identity.key_material().as_slice().to_vec()
    }) else {
        return;
    };

    let outcome = messaging.start(
        app.clone(),
        &messaging::vault_dir(app),
        &private_key,
        public_key,
        HttpRelayClient::from_env(),
    );
    private_key.zeroize();

    if let Err(e) = outcome {
        eprintln!("[wisp] messaging unavailable: {e}");
    }
}

type AppSession = Session<AppVolumeProvider>;

/// Event name the frontend subscribes to for pushed gate changes.
const STATUS_EVENT: &str = "wisp://status";

/// Idle timeout, stated here so Settings and the frontend timer cannot drift
/// apart. The frontend owns the timer; this is what it reports.
const IDLE_AFTER_MINUTES: u64 = 5;

/// Feedback for the passphrase field during setup.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PassphraseReport {
    estimated_bits: u32,
    /// True when the input scored as a run of dictionary words.
    is_word_phrase: bool,
    acceptable: bool,
    /// Why it was rejected, if it was.
    problem: Option<String>,
}

/// Current gate state. Cheap, and re-reads the hardware.
#[tauri::command]
fn gate_status(session: State<'_, Arc<AppSession>>) -> Status {
    session.refresh()
}

/// Attempts to unlock the identity on the inserted drive.
///
/// Takes the passphrase by value and wipes it before returning. The webview's
/// own copy is beyond our reach — a passphrase typed into a text field exists
/// in the renderer's memory, and no amount of care on this side changes that —
/// but the Rust-side copy does not outlive the call.
#[tauri::command]
fn unlock(
    app: tauri::AppHandle,
    mut passphrase: String,
    session: State<'_, Arc<AppSession>>,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Status, String> {
    let outcome = session.unlock(&passphrase).map_err(|e| e.to_string());
    passphrase.zeroize();

    if outcome.is_ok() {
        start_messaging(&app, &session, &messaging);
    }
    outcome
}

/// Redeems an invite code and creates an identity on a blank, bindable drive.
#[tauri::command]
fn register(
    app: tauri::AppHandle,
    invite_code: String,
    username: String,
    mut passphrase: String,
    session: State<'_, Arc<AppSession>>,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Status, String> {
    let outcome = session
        .register(&invite_code, &username, &passphrase)
        .map_err(|e| e.to_string());
    passphrase.zeroize();

    if outcome.is_ok() {
        start_messaging(&app, &session, &messaging);
    }
    outcome
}

/// Checks an invite code's format without contacting the relay.
///
/// Lets the setup screen catch a typo as it is typed, rather than spending one
/// of the relay's rate-limited redemption attempts on it.
#[tauri::command]
fn check_invite_code(candidate: String) -> bool {
    wisp_invite::InviteCode::parse(&candidate).is_ok()
}

/// Wipes the in-memory key and returns to the gate.
#[tauri::command]
fn lock(session: State<'_, Arc<AppSession>>, messaging: State<'_, Arc<Messaging>>) -> Status {
    // Messaging holds a copy of the identity key, so it goes first.
    messaging.stop();
    session.lock()
}

// --- Idle lock and biometrics ------------------------------------------------

/// The window the Hello prompt attaches to.
///
/// Desktop apps must anchor it; an unanchored prompt fails outside UWP.
#[cfg(windows)]
fn window_handle(app: &tauri::AppHandle) -> Result<wisp_biometric::WindowHandle, String> {
    let window = app
        .get_webview_window("main")
        .ok_or("the main window is gone")?;
    let hwnd = window.hwnd().map_err(|e| e.to_string())?;
    Ok(wisp_biometric::WindowHandle(hwnd.0 as isize))
}

#[cfg(not(windows))]
fn window_handle(_app: &tauri::AppHandle) -> Result<wisp_biometric::WindowHandle, String> {
    Ok(wisp_biometric::WindowHandle(0))
}

/// What this machine supports, re-checked on demand.
#[tauri::command]
fn biometric_capability() -> wisp_biometric::Availability {
    wisp_biometric::availability()
}

/// Covers the screen without wiping the key.
///
/// Driven by the frontend's inactivity timer. Safe to expose: it only ever
/// *removes* access, and coming back requires a check the renderer cannot
/// perform itself.
#[tauri::command]
fn begin_idle(session: State<'_, Arc<AppSession>>) -> Status {
    // Re-check hardware each time; enrolment can change while the app runs.
    session.set_biometrics_available(wisp_biometric::availability().is_available());
    session.begin_idle()
}

/// Resumes from idle via Windows Hello.
///
/// The prompt runs here, in Rust, and `resume_verified` is called only on a
/// genuine `Verified`. There is deliberately no command that resumes without
/// passing through this check, so a compromised renderer cannot simply ask.
#[tauri::command]
fn resume_biometric(
    app: tauri::AppHandle,
    session: State<'_, Arc<AppSession>>,
) -> Result<Status, String> {
    let handle = window_handle(&app)?;
    let outcome = wisp_biometric::verify(handle, "Unlock Wisp");

    if !outcome.is_verified() {
        return Err(match outcome {
            wisp_biometric::Verification::Declined => "Verification cancelled.".into(),
            wisp_biometric::Verification::RetriesExhausted => {
                "Too many attempts. Use your passphrase.".into()
            }
            wisp_biometric::Verification::Unavailable { reason } => reason.describe().to_string(),
            wisp_biometric::Verification::Failed { detail } => detail,
            wisp_biometric::Verification::Verified => unreachable!("checked above"),
        });
    }

    session.resume_verified().map_err(|e| e.to_string())
}

/// Resumes from idle with the passphrase. Always available.
#[tauri::command]
fn resume_passphrase(
    mut passphrase: String,
    session: State<'_, Arc<AppSession>>,
) -> Result<Status, String> {
    let outcome = session
        .resume_with_passphrase(&passphrase)
        .map_err(|e| e.to_string());
    passphrase.zeroize();
    outcome
}

/// Read-only facts for the Settings page.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    /// Which relay this build talks to, so a misconfigured endpoint is visible
    /// rather than something the user has to guess at.
    relay: String,
    idle_after_minutes: u64,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        relay: HttpRelayClient::from_env().base_url().to_string(),
        idle_after_minutes: IDLE_AFTER_MINUTES,
    }
}

// --- Trusted computer --------------------------------------------------------

/// What Settings needs to describe this computer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ComputerInfo {
    label: String,
    bindable: bool,
}

#[tauri::command]
fn computer_info() -> ComputerInfo {
    let identity = wisp_machine::identify();
    ComputerInfo {
        label: identity.label(),
        bindable: identity.is_bindable(),
    }
}

/// Turns trusted-computer binding on or off.
///
/// The passphrase is required in both directions and is not a policy check the
/// renderer could skip: the identity has to be decrypted and re-encrypted under
/// a different key schedule, so there is no path that changes the setting
/// without it.
#[tauri::command]
fn set_trusted_computer(
    enabled: bool,
    mut passphrase: String,
    session: State<'_, Arc<AppSession>>,
) -> Result<Status, String> {
    let outcome = session
        .set_trusted_computer(enabled, &passphrase)
        .map_err(|e| e.to_string());
    passphrase.zeroize();
    outcome
}

// --- Messaging ---------------------------------------------------------------

/// Peers we have history with. Empty until someone has been messaged — the
/// zero-state inbox is the absence of a directory, not a filtered view of one.
#[tauri::command]
fn conversations(messaging: State<'_, Arc<Messaging>>) -> Result<Vec<String>, String> {
    messaging.conversations()
}

#[tauri::command]
fn conversation(
    peer: String,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Vec<MessageView>, String> {
    let peer = parse_identity(&peer).ok_or("that is not a valid identity key")?;
    messaging.conversation(&peer)
}

/// Sends a message, establishing the session first if this is the first one.
#[tauri::command]
fn send_message(
    recipient: String,
    text: String,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<MessageView, String> {
    let recipient = parse_identity(&recipient).ok_or("that is not a valid identity key")?;
    if text.trim().is_empty() {
        return Err("message is empty".into());
    }
    messaging.send(recipient, text)
}

#[tauri::command]
fn messaging_ready(messaging: State<'_, Arc<Messaging>>) -> bool {
    messaging.is_active()
}

// --- Groups ------------------------------------------------------------------

/// Every group we know of.
///
/// Local only. The relay stores no groups, so this is assembled from what
/// members have told us, not fetched from anywhere.
#[tauri::command]
fn groups(messaging: State<'_, Arc<Messaging>>) -> Result<Vec<GroupView>, String> {
    messaging.groups()
}

#[tauri::command]
fn group_conversation(
    group: String,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Vec<GroupMessageView>, String> {
    let id = uuid::Uuid::parse_str(&group).map_err(|_| "that is not a valid group id")?;
    messaging.group_conversation(&id)
}

/// Creates a group and hands each member the key to read it.
#[tauri::command]
fn create_group(
    name: String,
    members: Vec<String>,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<GroupView, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a group needs a name".into());
    }

    let members = members
        .iter()
        .map(|member| parse_identity(member).ok_or("that is not a valid identity fingerprint"))
        .collect::<Result<Vec<_>, _>>()?;
    if members.is_empty() {
        return Err("a group needs at least one other member".into());
    }

    messaging.create_group(name, members)
}

#[tauri::command]
fn send_group_message(
    group: String,
    text: String,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<GroupMessageView, String> {
    let id = uuid::Uuid::parse_str(&group).map_err(|_| "that is not a valid group id")?;
    if text.trim().is_empty() {
        return Err("message is empty".into());
    }
    messaging.send_group(id, text)
}

/// Scores a candidate passphrase for the setup screen.
#[tauri::command]
fn assess_passphrase(mut candidate: String) -> PassphraseReport {
    let assessment = passphrase::assess(&candidate);
    candidate.zeroize();

    PassphraseReport {
        estimated_bits: assessment.estimated_bits,
        is_word_phrase: assessment.is_word_phrase,
        acceptable: assessment.is_acceptable(),
        problem: assessment.verdict.err().map(|e| e.to_string()),
    }
}

/// Generates a word phrase for the user to write down.
///
/// This necessarily hands a secret to the renderer — the user has to be able to
/// read it. It is generated on demand and never stored.
#[tauri::command]
fn generate_passphrase() -> String {
    let secret = passphrase::generate_phrase(passphrase::RECOMMENDED_WORD_COUNT);
    String::from_utf8_lossy(secret.as_slice()).into_owned()
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let provider = Arc::new(AppVolumeProvider::from_env());
            let relay = HttpRelayClient::from_env();
            eprintln!("[wisp] relay endpoint: {}", relay.base_url());

            let session: Arc<AppSession> =
                Arc::new(Session::new(Arc::clone(&provider), Arc::new(relay)));
            app.manage(Arc::clone(&session));

            let biometrics = wisp_biometric::availability();
            eprintln!("[wisp] biometrics: {}", biometrics.describe());
            session.set_biometrics_available(biometrics.is_available());

            let messaging = Arc::new(Messaging::default());
            app.manage(Arc::clone(&messaging));

            // Push gate changes rather than making the UI poll, so the
            // lock-on-removal transition reaches the screen as soon as the
            // watcher sees it.
            let app_handle = app.handle().clone();
            let watcher_session = Arc::clone(&session);
            let watcher_messaging = Arc::clone(&messaging);
            let watcher = Watcher::spawn(provider, DEFAULT_POLL_INTERVAL, move |_event| {
                let status = watcher_session.refresh();
                // Pulling the drive zeroizes the session key; messaging holds
                // its own copy, so it has to be torn down in the same breath.
                //
                // Keyed on the key being *gone*, not on whether the UI may
                // render: an idle session still holds its key and must keep
                // receiving, or messages would silently stop while the screen
                // is merely covered.
                if !watcher_session.is_unlocked() && watcher_messaging.is_active() {
                    watcher_messaging.stop();
                }
                let _ = app_handle.emit(STATUS_EVENT, status);
            });
            // Held in managed state so it lives as long as the app and is
            // stopped cleanly on exit.
            app.manage(watcher);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            gate_status,
            unlock,
            register,
            check_invite_code,
            lock,
            biometric_capability,
            app_info,
            computer_info,
            set_trusted_computer,
            begin_idle,
            resume_biometric,
            resume_passphrase,
            conversations,
            conversation,
            send_message,
            messaging_ready,
            groups,
            group_conversation,
            create_group,
            send_group_message,
            assess_passphrase,
            generate_passphrase
        ])
        .run(tauri::generate_context!())
        .expect("error while running Wisp");
}
