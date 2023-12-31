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

Superboring currently implements pretty much everything required to handle RSA signatures.