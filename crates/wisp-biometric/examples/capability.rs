//! Reports what this machine can do, without prompting.
//!
//! `cargo run -p wisp-biometric --example capability`
//!
//! The onboarding screen shows the same answer; this is for checking it from a
//! terminal when the UI says something surprising.

fn main() {
    let availability = wisp_biometric::availability();
    println!("{availability:?} — {}", availability.describe());
    println!(
        "biometric re-auth would be {}",
        if availability.is_available() {
            "offered"
        } else {
            "hidden, falling back to the passphrase"
        }
    );
}
