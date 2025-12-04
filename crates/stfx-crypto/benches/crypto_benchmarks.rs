use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use stfx_crypto::{
    ed25519::Ed25519Keypair,
    x25519::X25519Keypair,
    hash::{sha256, blake2b256},
    aead::ChaCha20Poly1305Cipher,
        Signer, Verifier, KeyAgreement, Aead,
};

// ============================================================================
// Ed25519 Benchmarks
// ============================================================================

fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_keypair_generate", |b| {
        b.iter(|| {
            black_box(Ed25519Keypair::generate());
        });
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let keypair = Ed25519Keypair::generate();
    let msg = b"The quick brown fox jumps over the lazy dog";
    
    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(keypair.sign(black_box(msg)).unwrap());
        });
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let keypair = Ed25519Keypair::generate();
    let msg = b"The quick brown fox jumps over the lazy dog";
    let sig = keypair.sign(msg).unwrap();
    let public_key = keypair.public_key();
    
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(public_key.verify(black_box(msg), black_box(&sig)).unwrap());
        });
    });
}

// ============================================================================
// X25519 Benchmarks
// ============================================================================

fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("x25519_keypair_generate", |b| {
        b.iter(|| {
            black_box(X25519Keypair::generate());
        });
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let alice = X25519Keypair::generate();
    let bob = X25519Keypair::generate();
    
    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| {
            black_box(alice.diffie_hellman(black_box(bob.public_key())));
        });
    });
}

// ============================================================================
// Hash Benchmarks (varying input sizes)
// ============================================================================

fn bench_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_functions");
    
    for size in [32, 64, 256, 1024, 4096].iter() {
        let data = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            b.iter(|| {
                black_box(sha256(black_box(data)));
            });
        });
        
        group.bench_with_input(BenchmarkId::new("blake2b256", size), &data, |b, data| {
            b.iter(|| {
                black_box(blake2b256(black_box(data)));
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// AEAD Benchmarks (ChaCha20Poly1305)
// ============================================================================

fn bench_aead_encrypt(c: &mut Criterion) {
    let cipher = ChaCha20Poly1305Cipher;
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let aad = b"metadata";
    
    let mut group = c.benchmark_group("aead_encrypt");
    
    for size in [64, 256, 1024, 4096].iter() {
        let plaintext = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, plaintext| {
            b.iter(|| {
                let mut data = plaintext.clone();
                cipher.encrypt(black_box(&key), black_box(&nonce), black_box(aad), black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }
    
    group.finish();
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let cipher = ChaCha20Poly1305Cipher;
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let aad = b"metadata";
    
    let mut group = c.benchmark_group("aead_decrypt");
    
    for size in [64, 256, 1024, 4096].iter() {
        let mut ciphertext = vec![0u8; *size];
        cipher.encrypt(&key, &nonce, aad, &mut ciphertext).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ciphertext| {
            b.iter(|| {
                let mut data = ciphertext.clone();
                cipher.decrypt(black_box(&key), black_box(&nonce), black_box(aad), black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    ed25519_benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify
);

criterion_group!(
    x25519_benches,
    bench_x25519_keygen,
    bench_x25519_dh
);

criterion_group!(
    hash_benches,
    bench_hash_functions
);

criterion_group!(
    aead_benches,
    bench_aead_encrypt,
    bench_aead_decrypt
);

criterion_main!(
    ed25519_benches,
    x25519_benches,
    hash_benches,
    aead_benches
);
