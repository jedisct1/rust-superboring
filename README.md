# ![Superboring](https://raw.github.com/jedisct1/rust-superboring/master/logo.png)

A Boring(SSL)-compatible API abstraction for Rust cryptographic implementations.

## What is Superboring?

Superboring hides the complexity, diversity and instability of cryptographic implementations written in Rust behind an emulation of the `boring` API (Rust excellent wrappers for BoringSSL).

This allows applications written using the `boring` API to be able to also use pure Rust implementations without having to maintain two code bases.

## Why use emulation instead of always using `boring`?

Here are valid reasons why using `boring` may sometimes not be an option.

All of them are just features that haven't been implemented in the `boring` crate yet, and that the `boring` maintainers would probably love getting help with, rather than people finding workarounds.

### WebAssembly

While BoringSSL itself [can be compiled to WebAssembly](https://github.com/jedisct1/boringssl-wasm), the `boring` crate currently doesn't support this.

### Symbol collisions with OpenSSL

OpenSSL and BoringSSL share a lot of symbols, which can cause collisions.

BoringSSL has the ability to prefix symbols in order to avoid this. But the `boring` crate currently doesn't support this.

## Static builds

The real `boring` crate supports static builds using `musl`, so emulation is not required. Just use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild):

```sh
cargo zigbuild --target=x86_64-unknown-linux-musl
```

## What is currently implemented?

- RSA operations: key generation (512 to 16384 bits), import/export (DER/PEM, PKCS1/PKCS8), encryption/decryption (raw, PKCS1v15, and OAEP with SHA-1 for both the label hash and MGF1, as with BoringSSL's `Padding::PKCS1_OAEP`), signatures (PKCS1v15 and PSS with SHA-256/384/512, with any of these for MGF1)
- ML-DSA post-quantum signatures: ML-DSA-44, ML-DSA-65 and ML-DSA-87, with key generation from random or seed, public key serialization, signing and verification
- AES key wrap: RFC 3394 key wrapping with AES-128 and AES-256
- AES-GCM: authenticated encryption with AES-128-GCM and AES-256-GCM, with streaming support and additional authenticated data
- Hash functions: SHA-256, SHA-384, SHA-512 (via `MessageDigest`)
- HMAC: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512

For RSA, Superboring accepts and rejects the same things as BoringSSL, even when the `rsa` crate underneath would do something else.

That means keys from 512 to 16384 bits, primes of different sizes, and PEM files as messy as BoringSSL tolerates.

Keys built from components are always accepted, and only fail once they are checked or used.

Private keys in DER are PKCS#1, both when reading and writing them, and PEM output is PKCS#1 too.

PKCS#1 v1.5 decryption returns an error when the padding is wrong, like BoringSSL does.
Don't let the other side find out whether decryption failed.

## WASI-Crypto

When compiling for `wasm32-wasip1`, the optional `wasi-crypto` feature uses the WASI-Crypto host extension through the `wasi-crypto-guest` crate for supported operations. With WasmEdge's `wasi_crypto` plugin, this currently accelerates RSA key generation/signing/verification for the plugin's supported RSA signature algorithms, AES-128-GCM, AES-256-GCM, HMAC-SHA-256 and HMAC-SHA-512. Operations not exposed by the plugin, such as AES key wrap, RSA encryption/OAEP, HMAC-SHA-384 and ML-DSA, keep using the Rust implementations.

```sh
cargo test --target wasm32-wasip1 --features wasi-crypto
```
