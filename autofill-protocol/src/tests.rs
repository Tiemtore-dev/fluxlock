use super::*;

fn first() -> (Handshake, Handshake, Vec<u8>) {
    let mut client = handshake(&[1; 64], true).unwrap();
    let server = handshake(&[2; 64], false).unwrap();
    let mut bytes = vec![0; MAX_HANDSHAKE];
    let n = client.write_message(&[], &mut bytes).unwrap();
    bytes.truncate(n);
    (client, server, bytes)
}
fn second() -> (Handshake, Handshake, Vec<u8>) {
    let (client, mut server, bytes) = first();
    server.read_message(&bytes, &mut []).unwrap();
    let mut bytes = vec![0; MAX_HANDSHAKE];
    let n = server.write_message(&[], &mut bytes).unwrap();
    bytes.truncate(n);
    (client, server, bytes)
}
fn complete() -> (Handshake, Handshake) {
    let (mut client, mut server, bytes) = second();
    client.read_message(&bytes, &mut []).unwrap();
    let mut bytes = vec![0; MAX_HANDSHAKE];
    let n = client.write_message(&[], &mut bytes).unwrap();
    server.read_message(&bytes[..n], &mut []).unwrap();
    (client, server)
}
#[test]
fn authenticated_hybrid_channel_rejects_tampering_replay_and_wrong_direction() {
    let (client, server) = complete();
    assert_eq!(client.remote_identity().unwrap(), public_identity(&[2; 64]));
    assert_eq!(server.remote_identity().unwrap(), public_identity(&[1; 64]));
    assert_eq!(client.get_handshake_hash().len(), 64);
    assert_eq!(client.get_handshake_hash(), server.get_handshake_hash());
    assert_eq!(fingerprint(client.get_handshake_hash()).len(), 71);
    let mut client = client.into_transport_mode().unwrap();
    let mut server = server.into_transport_mode().unwrap();
    let message = encrypt(&mut client, b"synthetic chosen password").unwrap();
    assert_eq!(
        &*decrypt(&mut server, &message).unwrap(),
        b"synthetic chosen password"
    );
    assert!(decrypt(&mut server, &message).is_err());
    let mut tampered = encrypt(&mut client, b"synthetic secret").unwrap();
    tampered[0] ^= 1;
    assert!(decrypt(&mut server, &tampered).is_err());
    assert!(decrypt(&mut client, &tampered).is_err());
}
#[test]
fn altered_server_signature_and_relocated_valid_signature_fail_closed() {
    let (mut client, _, mut bytes) = second();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(client.read_message(&bytes, &mut []).is_err());
    assert!(client.remote_identity().is_none());
    assert!(client.into_transport_mode().is_err());
    let (mut client, _, mut bytes) = second();
    let (_, _, other) = second();
    let n = bytes.len();
    bytes[n - SIGNATURE..].copy_from_slice(&other[other.len() - SIGNATURE..]);
    assert!(client.read_message(&bytes, &mut []).is_err());
    assert!(client.into_transport_mode().is_err());
}
#[test]
fn altered_client_signature_cannot_authorize_a_peer() {
    let (mut client, mut server, bytes) = second();
    client.read_message(&bytes, &mut []).unwrap();
    let mut bytes = vec![0; MAX_HANDSHAKE];
    let n = client.write_message(&[], &mut bytes).unwrap();
    bytes[n - 1] ^= 1;
    assert!(server.read_message(&bytes[..n], &mut []).is_err());
    assert!(server.remote_identity().is_none());
    assert!(server.into_transport_mode().is_err());
}
#[test]
fn genuine_mldsa_proof_cannot_replace_the_mlkem_shared_secret() {
    let (mut client, mut server, bytes) = first();
    server.read_message(&bytes, &mut []).unwrap();
    // Faulty/hostile responder signs a real transcript, but encapsulates to a
    // different recipient. Authentication alone must not yield a working key.
    let (_, different_key) = pq::kem_keypair().unwrap();
    server.kem_public = Some(different_key);
    let mut bytes = vec![0; MAX_HANDSHAKE];
    let n = server.write_message(&[], &mut bytes).unwrap();
    client.read_message(&bytes[..n], &mut []).unwrap();
    assert_eq!(client.remote_identity().unwrap(), public_identity(&[2; 64]));
    let n = client.write_message(&[], &mut bytes).unwrap();
    assert!(server.read_message(&bytes[..n], &mut []).is_err());
    assert!(server.into_transport_mode().is_err());
}
#[test]
fn classical_packets_bad_versions_roles_lengths_and_extra_bytes_are_rejected() {
    let (_, _, valid) = first();
    let mut bad = Vec::new();
    bad.push(vec![0; 32]); // A classical Noise XX message is never accepted.
    for (offset, value) in [(4, 1), (4, 3), (5, 2), (6, 255), (7, 0)] {
        let mut packet = valid.clone();
        packet[offset] = value;
        bad.push(packet);
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    bad.push(trailing);
    bad.push(valid[..valid.len() - 1].to_vec());
    bad.push(vec![0; MAX_HANDSHAKE + 1]);
    for packet in bad {
        let mut server = handshake(&[2; 64], false).unwrap();
        assert!(server.read_message(&packet, &mut []).is_err());
        assert!(server.read_message(&valid, &mut []).is_err()); // Failed means terminal.
        assert!(server.into_transport_mode().is_err());
    }
}
#[test]
fn premature_transport_or_application_payload_is_rejected() {
    assert!(handshake(&[1; 64], true)
        .unwrap()
        .into_transport_mode()
        .is_err());
    let (client, mut server, first) = first();
    assert!(client.into_transport_mode().is_err());
    server.read_message(&first, &mut []).unwrap();
    assert!(server.into_transport_mode().is_err());
    let (mut client, _, _) = second();
    let mut bytes = vec![0; MAX_HANDSHAKE];
    assert!(client
        .write_message(b"early credential", &mut bytes)
        .is_err());
    assert!(client.into_transport_mode().is_err());
}
#[test]
fn fresh_handshakes_with_persistent_identities_have_distinct_commitments() {
    let (first, _) = complete();
    let (second, _) = complete();
    assert_eq!(first.remote_identity(), second.remote_identity());
    assert_ne!(first.get_handshake_hash(), second.get_handshake_hash());
}
#[test]
fn pinned_identity_is_the_mldsa_key_not_just_the_classical_key() {
    let original = [1; 64];
    let mut changed_signature = original;
    changed_signature[32..].fill(2);
    let mut changed_noise = original;
    changed_noise[..32].fill(2);
    assert_ne!(
        public_identity(&original),
        public_identity(&changed_signature)
    );
    assert_eq!(public_identity(&original), public_identity(&changed_noise));
}

#[test]
fn mlkem_key_generation_matches_the_published_nist_acvp_vector() {
    use ml_kem::KeyExport;
    let seed = ml_kem::Seed::try_from(include_bytes!("../test-vectors/mlkem-seed.bin").as_slice())
        .unwrap();
    let key = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
    assert_eq!(
        key.encapsulation_key().to_bytes().as_slice(),
        include_bytes!("../test-vectors/mlkem-public.bin")
    );
}

#[test]
fn mldsa_key_generation_matches_the_published_nist_acvp_vector() {
    let key = pq::SigningMaterial::new(include_bytes!("../test-vectors/mldsa-seed.bin"));
    assert_eq!(
        key.public().as_slice(),
        include_bytes!("../test-vectors/mldsa-public.bin")
    );
}
