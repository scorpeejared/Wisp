fn main() {
    let identity = wisp_machine::identify();
    println!("computer:  {}", identity.label());
    match &identity.machine_id {
        Some(id) => println!("machine id: {}… ({} chars)", &id[..8.min(id.len())], id.len()),
        None => println!("machine id: none — this computer cannot be bound to"),
    }
    println!("bindable:  {}", identity.is_bindable());
}
