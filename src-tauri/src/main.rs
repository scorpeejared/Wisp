#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, Manager, State};
use zeroize::Zeroize;

use wisp_core::passphrase;
use wisp_session::{DriveInfo, Session, Status};
use wisp_usb::watcher::{Watcher, DEFAULT_POLL_INTERVAL};

mod dev_drive;
mod messaging;
mod relay_client;

use dev_drive::AppVolumeProvider;
use messaging::{
    parse_identity, GroupMessageView, GroupView, MessageView, Messaging,
};
use relay_client::HttpRelayClient;

fn start_messaging(app: &tauri::AppHandle, session: &AppSession, messaging: &Messaging) {
    let Some(public_key) = session.public_key() else {
        return;
    };

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

const STATUS_EVENT: &str = "wisp://status";

const IDLE_AFTER_MINUTES: u64 = 5;

#[tauri::command]
fn gate_status(session: State<'_, Arc<AppSession>>) -> Status {
    session.refresh()
}

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

#[tauri::command]
fn register(
    app: tauri::AppHandle,
    username: String,
    mut passphrase: String,
    session: State<'_, Arc<AppSession>>,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Status, String> {
    let outcome = session
        .register(&username, &passphrase)
        .map_err(|e| e.to_string());
    passphrase.zeroize();

    if outcome.is_ok() {
        start_messaging(&app, &session, &messaging);
    }
    outcome
}
#[tauri::command]
fn list_drives(session: State<'_, Arc<AppSession>>) -> Vec<DriveInfo> {
    session.drives()
}

#[tauri::command]
fn select_drive(
    mount_point: String,
    session: State<'_, Arc<AppSession>>,
    messaging: State<'_, Arc<Messaging>>,
) -> Result<Status, String> {
    if !session.drives().iter().any(|d| d.mount_point == mount_point) {
        return Err("that drive is not available".into());
    }
    messaging.stop();
    session.select_drive(&mount_point).map_err(|e| e.to_string())
}

#[tauri::command]
fn lock(session: State<'_, Arc<AppSession>>, messaging: State<'_, Arc<Messaging>>) -> Status {
    messaging.stop();
    session.lock()
}

// --- Idle lock and biometrics ------------------------------------------------

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

#[tauri::command]
fn biometric_capability() -> wisp_biometric::Availability {
    wisp_biometric::availability()
}

#[tauri::command]
fn begin_idle(session: State<'_, Arc<AppSession>>) -> Status {
    session.set_biometrics_available(wisp_biometric::availability().is_available());
    session.begin_idle()
}

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
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

// --- Groups ------------------------------------------------------------------

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

            let app_handle = app.handle().clone();
            let watcher_session = Arc::clone(&session);
            let watcher_messaging = Arc::clone(&messaging);
            let watcher = Watcher::spawn(provider, DEFAULT_POLL_INTERVAL, move |_event| {
                let status = watcher_session.refresh();
                if !watcher_session.is_unlocked() && watcher_messaging.is_active() {
                    watcher_messaging.stop();
                }
                let _ = app_handle.emit(STATUS_EVENT, status);
            });
            app.manage(watcher);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            gate_status,
            unlock,
            register,
            list_drives,
            select_drive,
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
            groups,
            group_conversation,
            create_group,
            send_group_message,
            generate_passphrase
        ])
        .run(tauri::generate_context!())
        .expect("error while running Wisp");
}
