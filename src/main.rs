use signal::{Alice, Bob};

pub fn main() {
    let mut bob = Bob::new();
    let mut alice = Alice::new();

    alice.x3dh(&bob);
    bob.x3dh(&alice);

    assert_eq!(bob.shared_secret, alice.shared_secret);

    alice.initialize_ratchets();
    bob.initialize_ratchets();

    let encrypted_message = alice.send(&mut bob, String::from("Hello Bob!").as_bytes());
    println!("Alice sends: {encrypted_message}");
    println!("Bob receives: {}", bob.recv(&hex::decode(encrypted_message).unwrap(), bob.get_public_key(&alice)));
    let encrypted_message = bob.send(&mut alice, String::from("Hello Alice!").as_bytes());
    println!("Bob sends: {encrypted_message}");
    println!("Alice receives: {}", alice.recv(&hex::decode(encrypted_message).unwrap(), alice.get_public_key(&bob)));
}
