//! Prints what this machine reports for trusted-computer binding.
//!
//! `cargo run -p wisp-machine --example whoami`

fn main() {
    let identity = wisp_machine::identify();
    println!("computer:  {}", identity.label());
    match &identity.machine_id {
        // Truncated: the full value is what the binding is derived from, and
        // there is no reason to put it on a terminal someone may screenshot.
        Some(id) => println!("machine id: {}… ({} chars)", &id[..8.min(id.len())], id.len()),
        None => println!("machine id: none — this computer cannot be bound to"),
    }
    println!("bindable:  {}", identity.is_bindable());
}
