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
