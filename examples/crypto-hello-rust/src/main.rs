use stfx_crypto::{
    aead, ed25519::Ed25519Keypair, encode::base64url_encode, hash, x25519::X25519Keypair,
    KeyAgreement, Signer,
};

fn main() {
    println!("=== Ed25519 Signing (Trait-based) ===");
    let sign_kp = Ed25519Keypair::generate();
    let msg = b"hello TSP".to_vec();
    let sig = sign_kp.sign(&msg).unwrap();

    let pub_raw = sign_kp.public_key().to_bytes();

    println!(
        "{{\n  \"msg_b64u\": \"{}\",\n  \"pub_b64u\": \"{}\",\n  \"sig_b64u\": \"{}\"\n}}",
        base64url_encode(&msg),
        base64url_encode(&pub_raw),
        base64url_encode(&sig),
    );

    println!("\n=== X25519 Key Agreement (Trait-based) ===");
    let alice = X25519Keypair::generate();
    let bob = X25519Keypair::generate();
    let shared_secret = alice.diffie_hellman(bob.public_key());
    println!(
        "{{\n  \"shared_secret_b64u\": \"{}\"\n}}",
        base64url_encode(&shared_secret)
    );

    println!("\n=== ChaCha20Poly1305 AEAD ===");
    let key = hash::sha256(b"key material");
    let nonce = [0u8; 12];
    let aad = b"envelope metadata";
    let mut plaintext = b"secret payload".to_vec();
    let original_len = plaintext.len();
    aead::encrypt(&key, &nonce, aad, &mut plaintext).unwrap();
    println!(
        "{{\n  \"ciphertext_b64u\": \"{}\",\n  \"tag_appended\": true\n}}",
        base64url_encode(&plaintext)
    );
    aead::decrypt(&key, &nonce, aad, &mut plaintext).unwrap();
    assert_eq!(plaintext.len(), original_len);
    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
}
