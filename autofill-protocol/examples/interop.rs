//! Synthetic stdio peer for WASM interoperability tests. Not installed as a host.
use fluxlock_autofill_protocol::{decrypt, encrypt, fingerprint, handshake, public_identity};
use std::io::{self, BufRead, Write};
fn decode(s: &str) -> Vec<u8> {
    s.trim()
        .as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn encode(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn main() {
    let mut lines = io::stdin().lock().lines();
    let key = [2; 64];
    let mut h = handshake(&key, false).unwrap();
    let mut tmp = [0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let mut out = [0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let first = decode(&lines.next().unwrap().unwrap());
    h.read_message(&first, &mut tmp).unwrap();
    let n = h.write_message(&[], &mut out).unwrap();
    println!("{}", encode(&out[..n]));
    io::stdout().flush().unwrap();
    let third = decode(&lines.next().unwrap().unwrap());
    h.read_message(&third, &mut tmp).unwrap();
    println!("{}", fingerprint(h.get_handshake_hash()));
    println!("{}", encode(&public_identity(&key)));
    io::stdout().flush().unwrap();
    let mut c = h.into_transport_mode().unwrap();
    for line in lines {
        let packet = decode(&line.unwrap());
        let plaintext = decrypt(&mut c, &packet).unwrap();
        let reply = encrypt(&mut c, &plaintext).unwrap();
        println!("{}", encode(&reply));
        io::stdout().flush().unwrap();
    }
}
