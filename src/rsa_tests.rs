//! RSA tests with fixed keys, checking that we accept and reject the same things as BoringSSL.

use crate::bn::BigNum;
use crate::hash::MessageDigest;
use crate::implementation::hex;
use crate::pkey::PKey;
use crate::reexports::rsa as rrsa;
use crate::rsa::{Padding, Rsa, RsaKey};
use crate::sign::{RsaPssSaltlen, Signer, Verifier};

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
// 1024 bits, with primes of 400 and 624 bits.
const RSA_UNBALANCED_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICTQIBAAKBgQDNzCe1ZCLg0o/Psp+A88L4es/IVZiQwG/qwRptaJba02duHjox
LTdSguFqQLv8RIlNI8WsjQdR4WH9aThDFEFQpCJhlZS9lhiEKgBECHLNEoQXlPD9
lIsABb1R05T+LirK1q9KTBC/16v9ZPSLQ6d6WxXVf/ZueLbJhTFn8ACjpwIDAQAB
AoGAK6oCTtE1OUBTtPywLPsLRg9AoL/Qg/3ggQ2Bnu8O+tTZ4BpXvHFciIwuaY3c
lNSx0QT2mtHUNK+h1XDIc0N46Y1bT9QpJW2ZHYvsktlbgLcwLdCAi/VVY66d4fKO
hoxzAitmtbungCYM9DDDKPiAHG0P8fBzb1mAIBYSCHJZ2dECMwD7z3hdeX+pZQvq
KUpuwSYv2eO/0rALLgF3FTYex3V+x/VuV4fms0F8eK4yvaaeTzNmmQJPANE4tADi
kpgUOpZufisXyLy21dWqAIk98fTyh8QhTHShesjmWY7vya2NJDV0cuvFI8H0fgxq
cOGH1Sni036NwCC4iUMBaTklPMdngsAEPwIyD+sisc4PevbvVOM9WFkPf/DnS+YW
yO4km5GUtUdorxYW9t3DsprcZfD/GigRE2rwVekCThAMXGpQ9tOpgZD2asEdcu1e
zOo1vxLH6J5UWCuoLjgoBsYQPUBkjkC8udFL3GDPX13KRjznkT8Lb0NmPbjQYLNh
1E2KdyrF+3KEMxhNewIyE7ic4qLFa/HoQR5zwK50AcyrH3hfUFJW3nWjd10jYEeQ
sMSBs5N0FBIeyHjs1X6CSg8=
-----END RSA PRIVATE KEY-----";
// 1025 bits, so PSS messages are one byte shorter than the modulus.
const RSA_1025_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQHUigW/b90RvKzziqqMsEDzV8jAqgHn/VHC1IrKW9eyLtSSQGvR
z0eZNSnpOlp58+lZ7HU2D7Y63QbiQxCFVnAQv6O/Rr+UGHfedzkAZ862igCBLxwo
5JDVQrx0KsN0sTViET5i3D56xaSUCtBabN7vf6yzSTVe8mOLTkfdaGZWSwIDAQAB
AoGASXgVG6YqV6AqzIuXX7U5kg7XU2K1JtABlJfoZX/OTEnsmjxQy9cBZqQ//Kri
ShI1qpyZ6o6/J+7FqBAVFJtvubWcznTQY7YPpUi3cHbSxg3rF0NQPqjLhf5M79bi
1O+Yol6sxCj0c9030ZwLfmPhGMEp9bjg4TxDALs3vrIrEAECQQD2PpWyFOfsd7lg
G3/gGu8POxNyi5XhUC4nsf6Z/wzW1unNf4cxUJocc+yC5eSITNuRSjPch6ZiCuMB
KuZIMFABAkEB5xn0KwjZRlw1Rgeps6bz91k46i1NxWGKcx28rc81iL7m4zlDbgft
P8+kW672M4CJew2Q2pv02G70ADmtel7mSwJBAJ7929PG0dSJnQSj3NYLLe2snCrq
W5TGG3b/4z71Qgn5a66Gt/isbUUPyFbgLsWesmpF+eRbJZ/KHbYkR9m2cAECQAb0
7+/NaI0AtCIT6fCO6d0WgSGXFA1Fn1yViCRTWUhisZl9L+Faa6EFritBDHMf2tbP
EsqMf6q3qvR13mxo/pECQGuhq3m8KTc5BjkwT/+pMw8c35V0XZgGZ15Lq8fGAGqh
dCLnDlMJ2n4NEIHhWGpRMvqHIHDVi9QTUH++quK0bVU=
-----END RSA PRIVATE KEY-----";

/// An invalid key keeps its components, but fails `check_key()` and can't be used.
fn assert_unusable(sk: &Rsa<crate::pkey::Private>, c: &[Vec<u8>; 8]) {
    assert!(!sk.check_key().unwrap());
    assert_eq!(&components(sk), c);
    // 0 and 1 would still decrypt with some broken keys in BoringSSL.
    let k = sk.size() as usize;
    let input = [vec![0u8; k - 1], vec![0x42]].concat();
    let mut plaintext = vec![0u8; k];
    assert!(sk
        .private_decrypt(&input, &mut plaintext, Padding::NONE)
        .is_err());
    let pkey = PKey::from_rsa(sk.clone()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    assert!(signer.sign_oneshot_to_vec(b"unusable").is_err());
}

#[test]
fn check_key_rejects_tiny_moduli() {
    let tiny: Rsa<crate::pkey::Private> = Rsa {
        rsa_key: RsaKey::Private(rrsa::PrivateKey::new_unchecked(&mut rand::rng(), 504).unwrap()),
        _marker: std::marker::PhantomData,
    };
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
fn valid_keys() {
    for pem in [RSA_1024_PEM, RSA_1025_PEM, RSA_2560_PEM, RSA_UNBALANCED_PEM] {
        let sk = Rsa::private_key_from_pem(pem.as_bytes()).unwrap();
        assert!(sk.check_key().unwrap());
        let pk = sk.public_key().unwrap();
        assert!(pk.check_key().unwrap());

        let c = components(&sk);
        let rebuilt = from_components(&c).unwrap();
        assert!(rebuilt.check_key().unwrap());
        assert_eq!(components(&rebuilt), c);
        assert_eq!(
            rebuilt.private_key_to_der().unwrap(),
            sk.private_key_to_der().unwrap()
        );

        let pkey = PKey::from_rsa(pk).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        let signature = sign(&rebuilt, b"valid");
        assert!(verifier.verify_oneshot(&signature, b"valid").unwrap());
    }
    let sk = Rsa::private_key_from_pem(RSA_2560_PEM.as_bytes()).unwrap();
    assert_eq!(sk.bits(), 2560);
    let sk = Rsa::private_key_from_pem(RSA_UNBALANCED_PEM.as_bytes()).unwrap();
    assert_eq!((sk.p().num_bits(), sk.q().num_bits()), (400, 624));
}

#[test]
fn invalid_components_are_kept() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let c = components(&sk);
    for i in 0..8 {
        let mut corrupted = c.clone();
        let last = corrupted[i].len() - 1;
        corrupted[i][last] ^= 2;
        let corrupted_key = from_components(&corrupted).unwrap();
        let der = corrupted_key.private_key_to_der().unwrap();
        assert!(Rsa::private_key_from_der(&der).is_err(), "component {i}");
        let pem = corrupted_key.private_key_to_pem().unwrap();
        assert!(Rsa::private_key_from_pem(&pem).is_err(), "component {i}");
        if i != 2 {
            assert_unusable(&corrupted_key, &corrupted);
            continue;
        }
        // BoringSSL doesn't need d when it has the CRT values, so the key still works.
        assert!(!corrupted_key.check_key().unwrap());
        assert_eq!(components(&corrupted_key), corrupted);
        assert_eq!(sign(&corrupted_key, b"no d"), sign(&sk, b"no d"));
    }
    let mut swapped = c.clone();
    swapped.swap(3, 4);
    assert_unusable(&from_components(&swapped).unwrap(), &swapped);

    // d still has to fit in the size of n, though.
    let mut long_d = c.clone();
    long_d[2].insert(0, 1);
    assert_unusable(&from_components(&long_d).unwrap(), &long_d);
}

#[test]
fn any_components_are_accepted() {
    // A textbook key, far too small to be used.
    let c = [
        vec![0x0c, 0xa1],
        vec![17],
        vec![0x0a, 0xc1],
        vec![61],
        vec![53],
        vec![53],
        vec![49],
        vec![38],
    ];
    let sk = from_components(&c).unwrap();
    assert_unusable(&sk, &c);
    let expected_der: [u8; 31] =
        hex("301d02010002020ca102011102020ac102013d020135020135020131020126");
    assert_eq!(sk.private_key_to_der().unwrap(), expected_der);
    assert!(Rsa::private_key_from_der(&sk.private_key_to_der().unwrap()).is_err());

    let pk = sk.public_key().unwrap();
    assert!(!pk.check_key().unwrap());
    assert_eq!(pk.size(), 2);
    let expected_pkcs1: [u8; 9] = hex("300702020ca1020111");
    assert_eq!(pk.public_key_to_der_pkcs1().unwrap(), expected_pkcs1);
    let mut ciphertext = [0u8; 2];
    assert!(pk
        .public_encrypt(&[0, 1], &mut ciphertext, Padding::NONE)
        .is_err());

    for (n, e) in [
        (vec![0x0c, 0xa2], vec![17]),
        (vec![0x0c, 0xa1], vec![1]),
        (vec![], vec![]),
    ] {
        let pk = Rsa::from_public_components(
            BigNum::from_slice(&n).unwrap(),
            BigNum::from_slice(&e).unwrap(),
        )
        .unwrap();
        assert!(!pk.check_key().unwrap());
        assert_eq!((pk.n().to_vec(), pk.e().to_vec()), (n, e));
        pk.public_key_to_der().unwrap();
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
const OPENSSL_OAEP_CIPHERTEXT: &str =
    "5f69a52e31ea9d9cd6bbf4d20cd6e20dc9ad6468b0385c5fae8e857c7b4942d1\
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
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let pk = sk.public_key().unwrap();
    let mut ciphertext = [0u8; 128];
    let len = pk
        .public_encrypt(OPENSSL_OAEP_PLAINTEXT, &mut ciphertext, Padding::PKCS1_OAEP)
        .unwrap();
    assert_eq!(len, 128);

    let mut em = [0u8; 128];
    sk.private_decrypt(&ciphertext, &mut em, Padding::NONE)
        .unwrap();
    assert_eq!(oaep_sha1_decode(&em), OPENSSL_OAEP_PLAINTEXT);
}

fn sign(sk: &Rsa<crate::pkey::Private>, msg: &[u8]) -> Vec<u8> {
    let pkey = PKey::from_rsa(sk.clone()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    signer.sign_oneshot_to_vec(msg).unwrap()
}

fn sign_pss(
    sk: &Rsa<crate::pkey::Private>,
    md: MessageDigest,
    mgf1_md: MessageDigest,
    salt_len: RsaPssSaltlen,
    msg: &[u8],
) -> Vec<u8> {
    let pkey = PKey::from_rsa(sk.clone()).unwrap();
    let mut signer = Signer::new(md, &pkey).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    signer.set_rsa_pss_saltlen(salt_len).unwrap();
    signer.set_rsa_mgf1_md(mgf1_md).unwrap();
    signer.sign_oneshot_to_vec(msg).unwrap()
}

fn verify_pss(
    pk: &Rsa<crate::pkey::Public>,
    md: MessageDigest,
    mgf1_md: MessageDigest,
    salt_len: RsaPssSaltlen,
    msg: &[u8],
    signature: &[u8],
) -> bool {
    let pkey = PKey::from_rsa(pk.clone()).unwrap();
    let mut verifier = Verifier::new(md, &pkey).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    verifier.set_rsa_pss_saltlen(salt_len).unwrap();
    verifier.set_rsa_mgf1_md(mgf1_md).unwrap();
    verifier.verify_oneshot(signature, msg).unwrap()
}

#[test]
fn private_keys_are_serialized_as_pkcs1() {
    use rrsa::pkcs8::EncodePrivateKey;

    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let (_, pkcs1) = rrsa::pkcs8::SecretDocument::from_pem(RSA_1024_PEM).unwrap();
    assert_eq!(sk.private_key_to_der().unwrap(), pkcs1.as_bytes());
    assert!(sk
        .private_key_to_pem()
        .unwrap()
        .starts_with(b"-----BEGIN RSA PRIVATE KEY-----\n"));

    // PKCS#8 is only accepted in PEM.
    let RsaKey::Private(key) = &sk.rsa_key else {
        unreachable!()
    };
    let pkcs8 = key.to_pkcs8_der().unwrap();
    assert!(Rsa::private_key_from_der(pkcs8.as_bytes()).is_err());
    let pkcs8_pem = key.to_pkcs8_pem(Default::default()).unwrap();
    let parsed = Rsa::private_key_from_pem(pkcs8_pem.as_bytes()).unwrap();
    assert_eq!(parsed.private_key_to_der().unwrap(), pkcs1.as_bytes());
}

#[test]
fn modulus_sizes_follow_boringssl() {
    use rrsa::pkcs1::der::Encode;

    let e = [1, 0, 1];
    for (bits, accepted) in [
        (511, false),
        (512, true),
        (1023, true),
        (8193, true),
        (16384, true),
        (16385, false),
    ] {
        let mut n = vec![0x5a; bits / 8 + 1];
        n[0] = 1 << ((bits - 1) % 8);
        if bits % 8 == 0 {
            n.remove(0);
            n[0] |= 0x80;
        }
        *n.last_mut().unwrap() |= 1;
        let pk = Rsa::from_public_components(
            BigNum::from_slice(&n).unwrap(),
            BigNum::from_slice(&e).unwrap(),
        )
        .unwrap();
        assert_eq!(pk.bits() as usize, bits);
        assert_eq!(pk.check_key().unwrap(), accepted, "{bits} bits");
        let mut ciphertext = vec![0u8; pk.size() as usize];
        let encrypted = pk.public_encrypt(b"size", &mut ciphertext, Padding::PKCS1);
        assert_eq!(encrypted.is_ok(), accepted, "{bits} bits");
        let der = rrsa::pkcs1::RsaPublicKeyRef {
            modulus: rrsa::pkcs1::UintRef::new(&n).unwrap(),
            public_exponent: rrsa::pkcs1::UintRef::new(&e).unwrap(),
        }
        .to_der()
        .unwrap();
        assert_eq!(
            Rsa::public_key_from_der_pkcs1(&der).is_ok(),
            accepted,
            "{bits} bits"
        );
    }
}

#[test]
fn rsassa_pss_public_keys_are_rejected() {
    use rrsa::pkcs1::der::{Decode, Encode};
    use rrsa::pkcs8::{DecodePublicKey, EncodePublicKey, ObjectIdentifier};

    let pk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    let der = pk.public_key_to_der().unwrap();
    let RsaKey::Public(key) = &pk.rsa_key else {
        unreachable!()
    };
    assert_eq!(der, key.to_public_key_der().unwrap().as_bytes());

    let mut spki = rrsa::pkcs8::SubjectPublicKeyInfoRef::from_der(&der).unwrap();
    spki.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    spki.algorithm.parameters = None;
    let rsassa_pss = spki.to_der().unwrap();
    // The rsa crate would take it.
    rrsa::PublicKey::from_public_key_der(&rsassa_pss).unwrap();
    assert!(Rsa::public_key_from_der(&rsassa_pss).is_err());
}

#[test]
fn raw_rsa_and_pkcs1_padding() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let pk = sk.public_key().unwrap();
    let decrypt = |em: &[u8]| {
        let (mut ciphertext, mut plaintext) = ([0u8; 128], [0u8; 128]);
        pk.public_encrypt(em, &mut ciphertext, Padding::NONE)
            .unwrap();
        sk.private_decrypt(&ciphertext, &mut plaintext, Padding::NONE)
            .unwrap();
        assert_eq!(plaintext.as_slice(), em);
        sk.private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1)
            .map(|len| plaintext[..len].to_vec())
    };
    let separator_at = |i: usize| {
        let mut em = vec![0x55u8; 128];
        em[0] = 0;
        em[1] = 2;
        em[i] = 0;
        em
    };

    // The padding has to be at least 8 bytes long.
    assert!(decrypt(&separator_at(9)).is_err());
    assert_eq!(decrypt(&separator_at(10)).unwrap(), vec![0x55; 117]);
    assert_eq!(decrypt(&separator_at(127)).unwrap(), Vec::<u8>::new());

    let mut no_separator = separator_at(10);
    no_separator[10] = 0x55;
    assert!(decrypt(&no_separator).is_err());
    for (i, x) in [(0, 1), (1, 1), (1, 0)] {
        let mut em = separator_at(10);
        em[i] = x;
        assert!(decrypt(&em).is_err(), "byte {i} set to {x}");
    }

    // Raw RSA needs a value of the same size as n, and smaller.
    let n = sk.n().to_vec();
    let mut out = [0u8; 128];
    assert!(pk.public_encrypt(&n, &mut out, Padding::NONE).is_err());
    assert!(sk.private_decrypt(&n, &mut out, Padding::NONE).is_err());
    assert!(pk.public_encrypt(&n[1..], &mut out, Padding::NONE).is_err());
}

#[test]
fn signer_options_follow_boringssl() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let pkey = PKey::from_rsa(sk.clone()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    assert_eq!(signer.rsa_padding().unwrap(), Padding::PKCS1);
    assert!(signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .is_err());
    assert!(signer.set_rsa_mgf1_md(MessageDigest::sha256()).is_err());
    assert!(signer.set_rsa_padding(Padding::PKCS1_OAEP).is_err());
    assert!(signer.set_rsa_padding(Padding::NONE).is_err());
    let signature = signer.sign_oneshot_to_vec(b"default padding").unwrap();
    assert_eq!(signature, sign(&sk, b"default padding"));

    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    assert!(signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::custom(-3))
        .is_err());
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)
        .unwrap();
    signer.set_rsa_mgf1_md(MessageDigest::sha512()).unwrap();

    let pkey = PKey::from_rsa(sk.public_key().unwrap()).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    assert!(verifier.set_rsa_padding(Padding::PKCS1_OAEP).is_err());
    assert!(verifier.set_rsa_mgf1_md(MessageDigest::sha256()).is_err());
    assert!(verifier
        .verify_oneshot(&signature, b"default padding")
        .unwrap());
}

// `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha512 -sigopt rsa_pss_saltlen:20` with RSA_1024_PEM.
const OPENSSL_PSS_MESSAGE: &[u8] = b"PSS with a different MGF1 hash";
const OPENSSL_PSS_SIGNATURE: &str =
    "5c14ca9c1f8a2e2880de5c6cd5b546a9b97a807b5b6a26216960e0acdbf9417e\
     657b66ba73487605a326283f03760343cedfa701f0e366ea97e958bfcf4120b9\
     31ddcabb75c1cd8d032344667b3aa1ee2e509706b2025012bbc08ec649279ff5\
     e3a726e93492257b5a0e49b06c12f2cb6e9deab6f266fdb79f0763598173e247";

#[test]
fn pss_follows_boringssl() {
    let sk = Rsa::private_key_from_pem(RSA_1024_PEM.as_bytes()).unwrap();
    let pk = sk.public_key().unwrap();
    let signature: [u8; 128] = hex(OPENSSL_PSS_SIGNATURE);
    let verify = |mgf1_md: MessageDigest, salt_len: RsaPssSaltlen| {
        let md = MessageDigest::sha256();
        verify_pss(&pk, md, mgf1_md, salt_len, OPENSSL_PSS_MESSAGE, &signature)
    };
    assert!(verify(MessageDigest::sha512(), RsaPssSaltlen::custom(20)));
    assert!(verify(
        MessageDigest::sha512(),
        RsaPssSaltlen::MAXIMUM_LENGTH
    ));
    assert!(!verify(
        MessageDigest::sha512(),
        RsaPssSaltlen::DIGEST_LENGTH
    ));
    assert!(!verify(MessageDigest::sha256(), RsaPssSaltlen::custom(20)));

    let mds = [
        MessageDigest::sha256(),
        MessageDigest::sha384(),
        MessageDigest::sha512(),
    ];
    let (md, salt_len) = (MessageDigest::sha384, RsaPssSaltlen::DIGEST_LENGTH);
    for mgf1_md in mds.clone() {
        let signature = sign_pss(&sk, md(), mgf1_md.clone(), salt_len, b"mgf1");
        for other in mds.clone() {
            let valid = verify_pss(&pk, md(), other.clone(), salt_len, b"mgf1", &signature);
            assert_eq!(valid, other == mgf1_md);
        }
    }

    // With a 1025-bit modulus, the largest salt is one byte shorter than it seems.
    let sk = Rsa::private_key_from_pem(RSA_1025_PEM.as_bytes()).unwrap();
    let pk = sk.public_key().unwrap();
    let md = MessageDigest::sha256;
    let signature = sign_pss(&sk, md(), md(), RsaPssSaltlen::MAXIMUM_LENGTH, b"max salt");
    let verify = |salt_len| verify_pss(&pk, md(), md(), salt_len, b"max salt", &signature);
    assert!(verify(RsaPssSaltlen::custom(128 - 32 - 2)));
    assert!(!verify(RsaPssSaltlen::custom(128 - 32 - 1)));
    assert!(!verify(RsaPssSaltlen::DIGEST_LENGTH));
    // When verifying, MAXIMUM_LENGTH accepts any salt length.
    assert!(verify(RsaPssSaltlen::MAXIMUM_LENGTH));
}

#[test]
fn generated_key_sizes_follow_boringssl() {
    for (bits, expected) in [
        (511, None),
        (512, Some(512)),
        (1000, Some(896)),
        (16385, None),
    ] {
        match Rsa::generate(bits) {
            Ok(sk) => {
                assert_eq!(Some(sk.bits()), expected, "{bits} bits");
                assert!(sk.check_key().unwrap());
            }
            Err(_) => assert_eq!(expected, None, "{bits} bits"),
        }
    }
}
