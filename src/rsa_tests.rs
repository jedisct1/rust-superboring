//! RSA tests with fixed keys: key checks, compared with what BoringSSL's `RSA_check_key()`
//! accepts, and OAEP, compared with OpenSSL.

use crate::bn::BigNum;
use crate::implementation::hex;
use crate::reexports::rsa as rrsa;
use crate::rsa::{Padding, Rsa, RsaKey};

// Generated with `openssl genpkey` (OpenSSL 3.6.4).
const RSA_1024_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDmj+sfBOoYd/YLGdnsz6tKtL3Awv/+mvkXQD05vAnZEmEFhu1Z
QKw2W5bq32e64pAH95spLsgvfEEsu4+IU+MACbff92H2ZD2eUBzzqFhhnYv9Z/13
eWQXYUVDmtA/VSftZdPLnCGQn3A1BBDC63KvNqh6bIIPT5uWAj3tIX9C2QIDAQAB
AoGAPux8QMT4lqD2t2Tgwu6SUxssxlTxxKzK2nufuggFsAaCEB4Y3Mj3twYcFBHQ
n4KByIrc/8pSvBLvPqQZsh0i0DU3ovGtHsyfYHOKneCjZNQ5aXvK8Bh8qNg+sBWh
ZZ0iQOD6x9VzOkb0jTqbGCq221fSAK169WUah6PiqhvmlRkCQQD2JWGPsOq8u5Wk
0KZ34ZXXoX7t7i4EsYzuRuCa/pspiCYwMFQzbsHq5A29n1KZx+LZwXYZEWBYuhcs
pdV5JVTXAkEA78rTsOL9mk8X4ofLS96LFZtKclMhrJ8OZqJSVaV0NvY6S8VnqVlM
dJ1E24zLPLLQC8H/Ju6ucr7Y/962Um9/zwJALSYcKBQmamnp/+o5rqGVL5EyzAe1
Ly02EXq0thlfcpXDk3E58JkvPpuIHbD8oLJ2XMTMmbqDNqMjnw/oASmkzwJBANyE
bSsVhF0c8X0snkOWU9e56Lu8QZKK72ZpTkhfEMHerHuz/YGakpoHayRwlRKr6nF1
pVy7UQhLBCpCOO8UhLcCQQDjKuS6WJ+5ieK6Bx4hkbOSUYxID6IP2G+CApeXDmQ7
PxiqFf+BaLJyRFAaECeux6cROTLHy01EWoTRmOQt8FYm
-----END RSA PRIVATE KEY-----";
// Version 1 (multi-prime) PKCS#1 key with three primes.
const RSA_3PRIME_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIE2gIBAQKCAQEArThz/B6/4BqKKcjHp2qSS2FiCR0FkKMGAFpvSS7EYnvBJ2Mo
bSKgJW4MHSJj2jUUUf0uWzk4dAhkT92TAXEuk0aiHevWQpV+m4YPyqx+dzX37vUG
iKfm+CBcho4hZsntVfmIExsXWCLSwc2Tgmv3vhynfzwLw2uuBIQ1+im8FRRVmlIx
Tlgq21Z2OTjE7FTICSuzKY+z9jLUlQ7Kx30lKazEwfgn6DIctj9o/TxCPYjessVO
2O2gIJBTjWfA7FcY49NJ54nkMzYvJTyWBhLxvuiydLZi+8PB21kc9HHCEnSM1lIr
YItySD1Spi95XXpJ0j0L+ckgXOyis7Sew3tqzQIDAQABAoIBAQCKlS+19aPs107S
Px/8gPap+C9Gu0FIhiS3A6MlGZVkdT4DFQGyzpDxYSmv5WOdn/mx3qzHru/LZStb
+hkyfiqVCV2KMrQocRHpu0fHDlnfZf4F32JqgK27YooKiPEktIiABy9SGMuc7uc2
BTUTvKi3UZAklTPfVxeetiB3qC3RGdTSQueJaRGu5YL9i+pihYTLlik9UrmoKnjf
xdwTZXTi7azzopYEAYkEB8Jvq/pRnFkupk6fr0hltFNPlaiJclo6zp7Kw4QpYmNC
LC6u3FfJOU2SfmuZiKDCR0UJK+ozNQq0DXgZWqhvRi8mlyh1kaV5oSMvtsPnszBF
LBV3OFYBAlYH6acUmAd240JKfgKAr8+6LWuct37OD3sljqsIdYG5gsculkux36KE
8I2vavNQeCh7OZf4QajwKhYFMYEyzCe8oVmDDUS4NTa+TJFcDxyO6pAQeHv3EwJW
Bwf3vDdq6GdWkDxDqItf1lVh7pC0ef6aSUJFOI7kSXGmh7fAVZazeYUO+c44hfXs
xMCmps0/63pjTKAuFUDdncxgMboTSzOBPAHlX9j53J5F9NabcQcCVgFPc0jYyFuq
1N6LMZToCIl3XhvM02YCcE1O7Anxk7MJ8jxHzW8+bqZ/Q6dqGbMYwvNtHTqSfQyQ
m6buhMvJvUbinXUzbE7pGRC4k1XgdsVAGO1xVm4bAlYFk2D2xi+mWwR/Xvr8doIq
kw0VRXWJZMjvHXmNL2uDfnfkGmiQtvBehpDosouKWApJwMincA6nayfBxSimPAlC
sKb76CaStSZf8tT13DfQp0assV8VEwJWBMWQnStfoyWJ8CuI052e1rtS+XlCV/MY
27R7ODpQSphGyZGxNDHoioCl0ys3vvhHvIOb6S+EsoPpi7Ok5nzsfiJqFNFBnbqJ
XoaFaj//T3+Pv+5Of74wggEMMIIBCAJWAx0OqrY4fmVqhDplMKomScCpC5zx92hP
OnfFtbdhEiBbE9PIoMLl/SlRWGjkdR+Qn5C+oexDvUPAqYURCu1gEz/vF2P/US71
1id8WHAhJVv/d17mw6kCVgIxmiD8rceZa7jpcF0etkWnIzUUi4UYkSKQO9Vy9UmR
VLsesTFcwjJjx3Y0yiwgZoWXtkpfL8eOkpSfNsftQ5GsralcgwxPu1X+kmW59BDf
xpv0WUKpAlYCfh9tDj2N5ugOKkDBlwJC4bSy15PnxGAxYUoxy0AMHlw985ODrpR+
oyTdJyVUqDIB4PrfCB7JgBqyBKW+DfwabZ/ZtM0u6Fz4FEg+5xP6lX66euXnow==
-----END RSA PRIVATE KEY-----";
const RSA_2560_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

fn private_key(rsa_key: rrsa::RsaPrivateKey) -> Rsa<crate::pkey::Private> {
    Rsa {
        rsa_key: RsaKey::Private(rsa_key),
        _marker: std::marker::PhantomData,
    }
}

#[test]
fn check_key_does_not_enforce_a_size_policy() {
    for pem in [RSA_1024_PEM, RSA_2560_PEM] {
        let sk = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
        assert!(sk.check_key().unwrap());
        let pk = sk.public_key().unwrap();
        assert!(pk.check_key().unwrap());
    }
    let sk = Rsa::private_key_from_pem(RSA_2560_PEM.as_bytes()).unwrap();
    assert_eq!(sk.bits(), 2560);
}

#[test]
fn check_key_rejects_d_not_below_n() {
    use rrsa::traits::{PrivateKeyParts, PublicKeyParts};

    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let RsaKey::Private(key) = &sk.rsa_key else {
        unreachable!()
    };
    let (n, e) = (key.n().clone(), key.e().clone());
    let (p, q) = (key.primes()[0].clone(), key.primes()[1].clone());
    let one = rrsa::BigUint::from(1u8);
    let phi = (&p - &one) * (&q - &one);
    // Still an inverse of e modulo p - 1 and q - 1, but larger than n.
    let d = key.d() + &phi * 2u8;
    assert!(d >= n);
    let big_d = rrsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).unwrap();
    assert!(!private_key(big_d).check_key().unwrap());
}

#[test]
fn check_key_rejects_tiny_moduli() {
    let mut rng = rand::thread_rng();
    let tiny = rrsa::RsaPrivateKey::new(&mut rng, 504).unwrap();
    let tiny = private_key(tiny);
    assert!(!tiny.check_key().unwrap());
    assert!(!tiny.public_key().unwrap().check_key().unwrap());
}

#[test]
fn public_check_key_validates_parameters() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let n = sk.n();
    let rebuilt =
        Rsa::from_public_components(n.clone(), BigNum::from_slice(&[1, 0, 1]).unwrap()).unwrap();
    assert!(rebuilt.check_key().unwrap());
    let e3 = Rsa::from_public_components(n, BigNum::from_slice(&[3]).unwrap()).unwrap();
    assert!(e3.check_key().unwrap());
}

fn components(sk: &Rsa<crate::pkey::Private>) -> [Vec<u8>; 8] {
    [
        sk.n().to_vec(),
        sk.e().to_vec(),
        sk.d().to_vec(),
        sk.p().to_vec(),
        sk.q().to_vec(),
        sk.dmp1().unwrap().to_vec(),
        sk.dmq1().unwrap().to_vec(),
        sk.iqmp().unwrap().to_vec(),
    ]
}

fn from_components(
    c: &[Vec<u8>; 8],
) -> Result<Rsa<crate::pkey::Private>, crate::error::ErrorStack> {
    let bn = |x: &Vec<u8>| BigNum::from_slice(x).unwrap();
    Rsa::from_private_components(
        bn(&c[0]),
        bn(&c[1]),
        bn(&c[2]),
        bn(&c[3]),
        bn(&c[4]),
        bn(&c[5]),
        bn(&c[6]),
        bn(&c[7]),
    )
}

#[test]
fn private_components_round_trip() {
    for pem in [RSA_1024_PEM, RSA_2560_PEM] {
        let sk = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
        let c = components(&sk);
        let rebuilt = from_components(&c).unwrap();
        assert!(rebuilt.check_key().unwrap());
        assert_eq!(components(&rebuilt), c);
        assert_eq!(
            rebuilt.private_key_to_der().unwrap(),
            sk.private_key_to_der().unwrap()
        );
    }
}

#[test]
fn every_inconsistent_component_is_rejected() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let c = components(&sk);
    for i in 0..8 {
        let mut corrupted = c.clone();
        let last = corrupted[i].len() - 1;
        corrupted[i][last] ^= 2;
        assert!(from_components(&corrupted).is_err(), "component {}", i);
    }
    // p and q swapped: the CRT values no longer match.
    let mut swapped = c.clone();
    swapped.swap(3, 4);
    assert!(from_components(&swapped).is_err());
}

fn reencoded(der: &[u8], change: impl FnOnce(&mut [Vec<u8>; 8])) -> Vec<u8> {
    use rrsa::pkcs1::der::Encode;
    use rrsa::pkcs1::UintRef;

    let key = rrsa::pkcs1::RsaPrivateKey::try_from(der).unwrap();
    let mut c = [
        key.modulus,
        key.public_exponent,
        key.private_exponent,
        key.prime1,
        key.prime2,
        key.exponent1,
        key.exponent2,
        key.coefficient,
    ]
    .map(|x| x.as_bytes().to_vec());
    change(&mut c);
    rrsa::pkcs1::RsaPrivateKey {
        modulus: UintRef::new(&c[0]).unwrap(),
        public_exponent: UintRef::new(&c[1]).unwrap(),
        private_exponent: UintRef::new(&c[2]).unwrap(),
        prime1: UintRef::new(&c[3]).unwrap(),
        prime2: UintRef::new(&c[4]).unwrap(),
        exponent1: UintRef::new(&c[5]).unwrap(),
        exponent2: UintRef::new(&c[6]).unwrap(),
        coefficient: UintRef::new(&c[7]).unwrap(),
        other_prime_infos: None,
    }
    .to_der()
    .unwrap()
}

#[test]
fn encoded_crt_values_are_checked() {
    use rrsa::pkcs1::der::pem::LineEnding;
    use rrsa::pkcs1::der::EncodePem;

    let (_, der) = rrsa::pkcs8::SecretDocument::from_pem(RSA_1024_PEM).unwrap();
    let der = der.as_bytes().to_vec();
    assert_eq!(reencoded(&der, |_| {}), der);
    Rsa::private_key_from_der(&der).unwrap();

    // exponent1, exponent2 and coefficient used to be dropped and recomputed.
    for i in 2..8 {
        let corrupted = reencoded(&der, |c| {
            let last = c[i].len() - 1;
            c[i][last] ^= 2;
        });
        assert!(
            Rsa::private_key_from_der(&corrupted).is_err(),
            "field {}",
            i
        );
        let key = rrsa::pkcs1::RsaPrivateKey::try_from(&corrupted[..]).unwrap();
        let pem = key.to_pem(LineEnding::LF).unwrap();
        assert!(
            Rsa::private_key_from_pem(pem.as_bytes()).is_err(),
            "field {}",
            i
        );
    }
}

#[test]
fn multi_prime_keys_are_rejected() {
    assert!(Rsa::private_key_from_pem(RSA_3PRIME_PEM.as_bytes()).is_err());
    let (_, der) = rrsa::pkcs8::SecretDocument::from_pem(RSA_3PRIME_PEM).unwrap();
    assert!(Rsa::private_key_from_der(der.as_bytes()).is_err());
}

// `openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep` with RSA_1024_PEM, which
// leaves both the label hash and MGF1 at their SHA-1 default, as BoringSSL does.
const OPENSSL_OAEP_PLAINTEXT: &[u8] = b"sixteen byte key";
const OPENSSL_OAEP_CIPHERTEXT: &str = "5f69a52e31ea9d9cd6bbf4d20cd6e20dc9ad6468b0385c5fae8e857c7b4942d1\
     fd140867f603fb568b59d77a2071b62c0ddcaec98d52a64c795150e05f90ec05\
     03a19ac472cb2f42dfd7b24d688d7de37ad176eb6759011a761610045496ab3e\
     56aef41a73c4c8ced6169fc6844e64746a52a5a7c50fa5bbbab76594c903daca";

#[test]
fn oaep_decrypts_openssl_ciphertexts() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let ciphertext: [u8; 128] = hex(OPENSSL_OAEP_CIPHERTEXT);
    let mut plaintext = [0u8; 128];
    let len = sk
        .private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1_OAEP)
        .unwrap();
    assert_eq!(&plaintext[..len], OPENSSL_OAEP_PLAINTEXT);

    let mut tampered = ciphertext;
    tampered[127] ^= 1;
    assert!(sk
        .private_decrypt(&tampered, &mut plaintext, Padding::PKCS1_OAEP)
        .is_err());
}

fn mgf1_sha1(seed: &[u8], len: usize) -> Vec<u8> {
    (0u32..)
        .flat_map(|counter| {
            let mut h = hmac_sha1_compact::Hash::new();
            h.update(seed);
            h.update(counter.to_be_bytes());
            h.finalize()
        })
        .take(len)
        .collect()
}

/// EME-OAEP decoding from RFC 8017 with SHA-1 and an empty label, written out so that the
/// check doesn't depend on the rsa crate's OAEP code.
fn oaep_sha1_decode(em: &[u8]) -> Vec<u8> {
    const EMPTY_LABEL_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    assert_eq!(em[0], 0);
    let (masked_seed, masked_db) = em[1..].split_at(20);
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(mgf1_sha1(masked_db, 20))
        .map(|(a, b)| a ^ b)
        .collect();
    let db: Vec<u8> = masked_db
        .iter()
        .zip(mgf1_sha1(&seed, masked_db.len()))
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(db[..20], hex::<20>(EMPTY_LABEL_SHA1));
    let separator = 20 + db[20..].iter().position(|&x| x != 0).unwrap();
    assert_eq!(db[separator], 1);
    db[separator + 1..].to_vec()
}

#[test]
fn oaep_encrypts_like_openssl() {
    use rrsa::pkcs1::DecodeRsaPrivateKey;
    use rrsa::traits::PublicKeyParts;

    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let pk = sk.public_key().unwrap();
    let mut ciphertext = [0u8; 128];
    let len = pk
        .public_encrypt(OPENSSL_OAEP_PLAINTEXT, &mut ciphertext, Padding::PKCS1_OAEP)
        .unwrap();
    assert_eq!(len, 128);

    let key = rrsa::RsaPrivateKey::from_pkcs1_pem(RSA_1024_PEM).unwrap();
    let c = rrsa::BigUint::from_bytes_be(&ciphertext);
    let m = rrsa::hazmat::rsa_decrypt_and_check(&key, None::<&mut rand::rngs::ThreadRng>, &c)
        .unwrap();
    let mut em = vec![0u8; key.size()];
    let m = m.to_bytes_be();
    em[key.size() - m.len()..].copy_from_slice(&m);
    assert_eq!(oaep_sha1_decode(&em), OPENSSL_OAEP_PLAINTEXT);
}
