use hmac_sha256::Hash as Sha256;
use hmac_sha512::sha384::Hash as Sha384;
use hmac_sha512::Hash as Sha512;
use std::ffi::c_int;

#[allow(unused_imports)]
use rrsa::pkcs1::{
    DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _, EncodeRsaPrivateKey as _,
    EncodeRsaPublicKey as _,
};
#[allow(unused_imports)]
use rrsa::pkcs8::{
    AssociatedOid as _, DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _,
    EncodePublicKey as _,
};
#[allow(unused_imports)]
use rrsa::signature::{
    DigestSigner as _, DigestVerifier as _, Keypair as _, KeypairRef as _, PrehashSignature as _,
    RandomizedDigestSigner as _, RandomizedSigner as _, SignatureEncoding as _, Signer as _,
    SignerMut as _, Verifier as _,
};
#[allow(unused_imports)]
use rrsa::traits::{
    Decryptor as _, EncryptingKeypair as _, PaddingScheme as _, PrivateKeyParts as _,
    PublicKeyParts as _, RandomizedDecryptor as _, RandomizedEncryptor as _, SignatureScheme as _,
};

pub mod reexports {
    pub use hmac_sha256;
    pub use hmac_sha512;
    pub use rand;
    pub use rrsa as rsa;
}

#[allow(unused_imports)]
use rsa::*;
pub mod rsa {
    use rrsa::pkcs8::EncodePrivateKey;

    #[allow(unused_imports)]
    use super::*;

    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub enum RsaKey {
        #[default]
        None,
        Public(rrsa::RsaPublicKey),
        Private(rrsa::RsaPrivateKey),
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Rsa<T> {
        pub rsa_key: RsaKey,
        pub _marker: std::marker::PhantomData<T>,
    }

    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    pub enum PaddingId {
        #[default]
        None,
        Pkcs1,
        Pkcs1Pss,
        Pkcs1Oaep,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct Padding {
        id: PaddingId,
    }

    impl Padding {
        pub const NONE: Padding = Padding {
            id: PaddingId::None,
        };

        pub const PKCS1: Padding = Padding {
            id: PaddingId::Pkcs1,
        };

        pub const PKCS1_PSS: Padding = Padding {
            id: PaddingId::Pkcs1Pss,
        };

        pub const PKCS1_OAEP: Padding = Padding {
            id: PaddingId::Pkcs1Oaep,
        };
    }

    impl Rsa<Public> {
        pub fn new() -> Self {
            Rsa {
                rsa_key: RsaKey::None,
                _marker: std::marker::PhantomData,
            }
        }

        pub fn size(&self) -> u32 {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            rsa_key.size() as u32
        }

        pub fn bits(&self) -> u32 {
            self.size() * 8
        }

        pub fn check_key(&self) -> Result<bool, ErrorStack> {
            match self.bits() {
                2048 | 3072 | 4096 => Ok(true),
                _ => Ok(false),
            }
        }

        pub fn public_key_from_der(der: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_public_key = rrsa::RsaPublicKey::from_public_key_der(der)
                .map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_key = RsaKey::Public(rsa_public_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn public_key_from_der_pkcs1(der: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_public_key = rrsa::RsaPublicKey::from_pkcs1_der(der)
                .map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_key = RsaKey::Public(rsa_public_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn public_key_from_pem(pem: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_pem = std::str::from_utf8(pem).map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_public_key = rrsa::RsaPublicKey::from_public_key_pem(rsa_pem)
                .map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_key = RsaKey::Public(rsa_public_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn public_key_from_pem_pkcs1(pem: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_pem = std::str::from_utf8(pem).map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_public_key = rrsa::RsaPublicKey::from_pkcs1_pem(rsa_pem)
                .map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_key = RsaKey::Public(rsa_public_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_public_key = rrsa::RsaPublicKey::new(n.rsa_bn, e.rsa_bn)
                .map_err(|_| ErrorStack::InvalidPublicKey)?;
            let rsa_key = RsaKey::Public(rsa_public_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn n(&self) -> BigNum {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.n().clone(),
            }
        }

        pub fn e(&self) -> BigNum {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.e().clone(),
            }
        }

        pub fn public_key_to_der(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            Ok(rsa_key
                .to_public_key_der()
                .map_err(|_| ErrorStack::InvalidPublicKey)?
                .into_vec())
        }

        pub fn public_key_to_der_pkcs1(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            Ok(rsa_key
                .to_pkcs1_der()
                .map_err(|_| ErrorStack::InvalidPublicKey)?
                .into_vec())
        }

        pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            Ok(rsa_key
                .to_public_key_pem(Default::default())
                .map_err(|_| ErrorStack::InvalidPublicKey)?
                .into_bytes())
        }

        pub fn public_key_to_pem_pkcs1(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            Ok(rsa_key
                .to_pkcs1_pem(Default::default())
                .map_err(|_| ErrorStack::InvalidPublicKey)?
                .into_bytes())
        }

        pub fn public_encrypt(
            &self,
            from: &[u8],
            to: &mut [u8],
            padding: Padding,
        ) -> Result<usize, ErrorStack> {
            let rsa_key = if let RsaKey::Public(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            let mut rng = rand::thread_rng();
            let c = match padding.id {
                PaddingId::None => panic!("Padding not set"),
                PaddingId::Pkcs1 => rsa_key
                    .encrypt(&mut rng, rrsa::Pkcs1v15Encrypt, from)
                    .map_err(|_| ErrorStack::InvalidPublicKey)?,
                PaddingId::Pkcs1Pss => panic!("Invalid padding for encryption"),
                PaddingId::Pkcs1Oaep => rsa_key
                    .encrypt(&mut rng, rrsa::Oaep::new::<Sha256>(), from)
                    .map_err(|_| ErrorStack::InvalidPublicKey)?,
            };
            let len = c.len();
            to.fill(0);
            to[0..len].copy_from_slice(&c);
            Ok(len)
        }
    }

    impl Rsa<Private> {
        pub fn generate(bits: u32) -> Result<Rsa<Private>, ErrorStack> {
            match bits {
                2048 | 3072 | 4096 => {}
                _ => return Err(ErrorStack::UnsupportedModulus),
            };
            let mut rng = rand::thread_rng();
            let rsa_key = rrsa::RsaPrivateKey::new(&mut rng, bits as _)
                .map_err(|_| ErrorStack::InternalError)?;
            let rsa_key = RsaKey::Private(rsa_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn size(&self) -> u32 {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            rsa_key.size() as u32
        }

        pub fn bits(&self) -> u32 {
            self.size() * 8
        }

        pub fn check_key(&self) -> Result<bool, ErrorStack> {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            match self.bits() {
                2048 | 3072 | 4096 => {}
                _ => return Ok(false),
            };
            if rsa_key.validate().is_err() {
                return Ok(false);
            }
            Ok(true)
        }

        pub fn public_key(&self) -> Result<Rsa<Public>, ErrorStack> {
            let n = self.n();
            let e = self.e();
            Rsa::from_public_components(n, e)
        }

        pub fn private_key_from_pem(pem: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
            let rsa_pem = std::str::from_utf8(pem).map_err(|_| ErrorStack::InvalidPrivateKey)?;
            let rsa_pem = rsa_pem.trim();
            let mut rsa_key = rrsa::RsaPrivateKey::from_pkcs8_pem(rsa_pem)
                .or_else(|_| rrsa::RsaPrivateKey::from_pkcs1_pem(rsa_pem))
                .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            rsa_key
                .validate()
                .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            rsa_key
                .precompute()
                .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            let rsa_key = RsaKey::Private(rsa_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn private_key_from_der(der: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
            let rsa_key = rrsa::RsaPrivateKey::from_pkcs8_der(der)
                .or_else(|_| rrsa::RsaPrivateKey::from_pkcs1_der(der))
                .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            let rsa_key = RsaKey::Private(rsa_key);
            Ok(Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            })
        }

        pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            let bytes = rsa_key
                .to_pkcs8_pem(Default::default())
                .map_err(|_| ErrorStack::InvalidPrivateKey)?
                .as_bytes()
                .to_vec();
            Ok(bytes)
        }

        pub fn private_key_to_der(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            let bytes = rsa_key
                .to_pkcs8_der()
                .map_err(|_| ErrorStack::InvalidPrivateKey)?
                .as_bytes()
                .to_vec();
            Ok(bytes)
        }

        pub fn n(&self) -> BigNum {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.n().clone(),
            }
        }

        pub fn d(&self) -> BigNum {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.d().clone(),
            }
        }

        pub fn e(&self) -> BigNum {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.e().clone(),
            }
        }

        pub fn p(&self) -> BigNum {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.primes()[0].clone(),
            }
        }

        pub fn q(&self) -> BigNum {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            BigNum {
                rsa_bn: rsa_key.primes()[1].clone(),
            }
        }

        pub fn private_decrypt(
            &self,
            from: &[u8],
            to: &mut [u8],
            padding: Padding,
        ) -> Result<usize, ErrorStack> {
            let rsa_key = if let RsaKey::Private(x) = &self.rsa_key {
                x
            } else {
                unreachable!();
            };
            let mut rng = rand::thread_rng();
            let m = match padding.id {
                PaddingId::None => panic!("Padding not set"),
                PaddingId::Pkcs1 => rsa_key
                    .decrypt_blinded(&mut rng, rrsa::Pkcs1v15Encrypt, from)
                    .map_err(|_| ErrorStack::InvalidPrivateKey)?,
                PaddingId::Pkcs1Pss => panic!("Invalid padding for decryption"),
                PaddingId::Pkcs1Oaep => rsa_key
                    .decrypt_blinded(&mut rng, rrsa::Oaep::new::<Sha256>(), from)
                    .map_err(|_| ErrorStack::InvalidPrivateKey)?,
            };
            let len = m.len();
            to.fill(0);
            to[0..len].copy_from_slice(&m);
            Ok(len)
        }
    }
}

#[allow(unused_imports)]
use error::*;
pub mod error {
    #[allow(unused_imports)]
    use super::*;

    pub enum ErrorStack {
        InternalError,
        InvalidPrivateKey,
        InvalidPublicKey,
        Overflow,
        UnsupportedModulus,
        KeyError,
    }

    impl std::fmt::Display for ErrorStack {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                ErrorStack::InternalError => write!(f, "Internal error"),
                ErrorStack::InvalidPrivateKey => write!(f, "Invalid private key"),
                ErrorStack::InvalidPublicKey => write!(f, "Invalid public key"),
                ErrorStack::Overflow => write!(f, "Overflow"),
                ErrorStack::UnsupportedModulus => write!(f, "Unsupported modulus"),
                ErrorStack::KeyError => write!(f, "Key error"),
            }
        }
    }

    impl std::fmt::Debug for ErrorStack {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Superboring error: {}", self)
        }
    }

    impl std::error::Error for ErrorStack {}
}

#[allow(unused_imports)]
use aes::*;
pub mod aes {
    #[allow(unused_imports)]
    use super::*;

    use aes_keywrap::{Aes128KeyWrapAligned, Aes256KeyWrapAligned};

    #[derive(Debug)]
    enum AesKeyInner {
        Aes128(Aes128KeyWrapAligned),
        Aes256(Aes256KeyWrapAligned),
    }

    #[derive(Debug)]
    pub struct AesKey {
        inner: AesKeyInner,
    }

    pub type KeyError = ErrorStack;

    impl AesKey {
        pub fn new_encrypt(key: &[u8]) -> Result<AesKey, KeyError> {
            let inner = match key.len() {
                16 => {
                    let key_arr: [u8; 16] = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                    AesKeyInner::Aes128(Aes128KeyWrapAligned::new(&key_arr))
                }
                32 => {
                    let key_arr: [u8; 32] = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                    AesKeyInner::Aes256(Aes256KeyWrapAligned::new(&key_arr))
                }
                _ => return Err(ErrorStack::KeyError),
            };
            Ok(AesKey { inner })
        }

        pub fn new_decrypt(key: &[u8]) -> Result<AesKey, KeyError> {
            Self::new_encrypt(key)
        }
    }

    pub fn wrap_key(
        key: &AesKey,
        iv: Option<[u8; 8]>,
        out: &mut [u8],
        in_: &[u8],
    ) -> Result<usize, KeyError> {
        if iv.is_some() {
            return Err(ErrorStack::KeyError);
        }
        let wrapped = match &key.inner {
            AesKeyInner::Aes128(k) => k.encapsulate(in_).map_err(|_| ErrorStack::KeyError)?,
            AesKeyInner::Aes256(k) => k.encapsulate(in_).map_err(|_| ErrorStack::KeyError)?,
        };
        if out.len() < wrapped.len() {
            return Err(ErrorStack::Overflow);
        }
        out[..wrapped.len()].copy_from_slice(&wrapped);
        Ok(wrapped.len())
    }

    pub fn unwrap_key(
        key: &AesKey,
        iv: Option<[u8; 8]>,
        out: &mut [u8],
        in_: &[u8],
    ) -> Result<usize, KeyError> {
        if iv.is_some() {
            return Err(ErrorStack::KeyError);
        }
        let unwrapped = match &key.inner {
            AesKeyInner::Aes128(k) => k.decapsulate(in_).map_err(|_| ErrorStack::KeyError)?,
            AesKeyInner::Aes256(k) => k.decapsulate(in_).map_err(|_| ErrorStack::KeyError)?,
        };
        if out.len() < unwrapped.len() {
            return Err(ErrorStack::Overflow);
        }
        out[..unwrapped.len()].copy_from_slice(&unwrapped);
        Ok(unwrapped.len())
    }
}

#[allow(unused_imports)]
use bn::*;
pub mod bn {
    #[allow(unused_imports)]
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BigNum {
        pub rsa_bn: rrsa::BigUint,
    }

    pub type BigNumRef<'a> = BigNum;

    impl BigNum {
        pub fn from_slice(slice: &[u8]) -> Result<Self, ErrorStack> {
            let rsa_bn = rrsa::BigUint::from_bytes_be(slice);
            Ok(BigNum { rsa_bn })
        }

        pub fn to_vec(&self) -> Vec<u8> {
            self.rsa_bn.to_bytes_be()
        }

        pub fn to_owned(&self) -> Result<BigNum, ErrorStack> {
            Ok(self.clone())
        }
    }
}

#[allow(unused_imports)]
use hash::*;
pub mod hash {
    #[allow(unused_imports)]
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum MessageDigest {
        Sha256,
        Sha384,
        Sha512,
    }

    impl MessageDigest {
        pub fn sha256() -> MessageDigest {
            MessageDigest::Sha256
        }

        pub fn sha384() -> MessageDigest {
            MessageDigest::Sha384
        }

        pub fn sha512() -> MessageDigest {
            MessageDigest::Sha512
        }
    }
}

#[allow(unused_imports)]
use pkey::*;
pub mod pkey {
    #[allow(unused_imports)]
    use super::*;

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum Public {}

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum Private {}

    pub trait HasPublic {}

    impl HasPublic for Public {}

    pub trait HasPrivate {}

    impl HasPrivate for Private {}

    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub enum PKey<T> {
        #[default]
        None,
        Rsa(Rsa<T>),
    }

    impl<T> PKey<T> {
        pub fn from_rsa(rsa: Rsa<T>) -> Result<PKey<T>, ErrorStack> {
            Ok(PKey::Rsa(rsa))
        }
    }
}

#[allow(unused_imports)]
use sign::*;
pub mod sign {
    #[allow(unused_imports)]
    use super::*;

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct RsaPssSaltlen {
        pub len: c_int,
    }

    impl Default for RsaPssSaltlen {
        fn default() -> Self {
            RsaPssSaltlen { len: -1 }
        }
    }

    impl RsaPssSaltlen {
        pub fn custom(len: c_int) -> Self {
            RsaPssSaltlen { len }
        }

        pub const DIGEST_LENGTH: RsaPssSaltlen = RsaPssSaltlen { len: -1 };
        pub const MAXIMUM_LENGTH: RsaPssSaltlen = RsaPssSaltlen { len: -2 };
    }

    #[derive(Clone, Default)]
    pub enum AnyHash {
        #[default]
        None,
        Sha256(Sha256),
        Sha384(Sha384),
        Sha512(Sha512),
    }

    #[derive(Clone)]
    pub struct Signer<'t, T> {
        pub message_digest: MessageDigest,
        pub pkey_ref: &'t PKey<T>,
        pub padding: Padding,
        pub salt_len: RsaPssSaltlen,
        pub any_hash: AnyHash,
    }

    impl<'t, T> Signer<'t, T> {
        pub fn new(type_: MessageDigest, pkey: &'t PKey<T>) -> Result<Signer<'t, T>, ErrorStack>
        where
            T: HasPrivate,
        {
            let any_hash = match type_ {
                MessageDigest::Sha256 => AnyHash::Sha256(Sha256::new()),
                MessageDigest::Sha384 => AnyHash::Sha384(Sha384::new()),
                MessageDigest::Sha512 => AnyHash::Sha512(Sha512::new()),
            };
            Ok(Signer {
                message_digest: type_,
                pkey_ref: pkey,
                padding: Padding::NONE,
                salt_len: RsaPssSaltlen::default(),
                any_hash,
            })
        }

        pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
            self.padding = padding;
            Ok(())
        }

        pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
            Ok(self.padding)
        }

        pub fn set_rsa_pss_saltlen(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
            self.salt_len = len;
            Ok(())
        }

        pub fn rsa_pss_saltlen(&self) -> Result<RsaPssSaltlen, ErrorStack> {
            Ok(self.salt_len)
        }

        pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
            match &mut self.any_hash {
                AnyHash::None => unreachable!("AnyHash::None"),
                AnyHash::Sha256(x) => x.update(buf),
                AnyHash::Sha384(x) => x.update(buf),
                AnyHash::Sha512(x) => x.update(buf),
            };
            Ok(())
        }

        #[allow(clippy::len_without_is_empty)]
        pub fn len(&self) -> Result<usize, ErrorStack> {
            let rsa_key = if let PKey::Rsa(x) = self.pkey_ref {
                x
            } else {
                unreachable!();
            };
            let rsa_key = if let RsaKey::Private(x) = &rsa_key.rsa_key {
                x
            } else {
                unreachable!();
            };
            Ok(rsa_key.size())
        }

        pub fn sign(&self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
            let sig = self.sign_to_vec()?;
            if buf.len() < sig.len() {
                return Err(ErrorStack::Overflow);
            }
            buf.copy_from_slice(&sig);
            Ok(sig.len())
        }

        pub fn sign_to_vec(&self) -> Result<Vec<u8>, ErrorStack> {
            let rsa_key = if let PKey::Rsa(x) = self.pkey_ref {
                x
            } else {
                unreachable!();
            };
            let rsa_key = if let RsaKey::Private(x) = &rsa_key.rsa_key {
                x
            } else {
                unreachable!();
            };
            let mut rng = rand::thread_rng();
            let rsa_key = rsa_key.clone();
            match self.padding {
                Padding::NONE => panic!("Padding not set"),
                Padding::PKCS1 => match self.any_hash {
                    AnyHash::None => unreachable!("AnyHash::None"),
                    AnyHash::Sha256(x) => {
                        let signing_key = rrsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key);
                        Ok(signing_key
                            .sign_digest_with_rng(&mut rng, x)
                            .to_bytes()
                            .into_vec())
                    }
                    AnyHash::Sha384(x) => {
                        let signing_key = rrsa::pkcs1v15::SigningKey::<Sha384>::new(rsa_key);
                        Ok(signing_key
                            .sign_digest_with_rng(&mut rng, x)
                            .to_bytes()
                            .into_vec())
                    }
                    AnyHash::Sha512(x) => {
                        let signing_key = rrsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_key);
                        Ok(signing_key
                            .sign_digest_with_rng(&mut rng, x)
                            .to_bytes()
                            .into_vec())
                    }
                },
                Padding::PKCS1_PSS => {
                    let hash_len = match self.message_digest {
                        MessageDigest::Sha256 => 32,
                        MessageDigest::Sha384 => 48,
                        MessageDigest::Sha512 => 64,
                    };
                    let salt_len = match self.salt_len.len {
                        -1 => hash_len,
                        -2 => rsa_key.size() - hash_len - 2,
                        x => x as _,
                    };
                    match self.any_hash {
                        AnyHash::None => unreachable!("AnyHash::None"),
                        AnyHash::Sha256(x) => {
                            let signing_key =
                                rrsa::pss::BlindedSigningKey::<Sha256>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(signing_key
                                .sign_digest_with_rng(&mut rng, x)
                                .to_bytes()
                                .into_vec())
                        }
                        AnyHash::Sha384(x) => {
                            let signing_key =
                                rrsa::pss::BlindedSigningKey::<Sha384>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(signing_key
                                .sign_digest_with_rng(&mut rng, x)
                                .to_bytes()
                                .into_vec())
                        }
                        AnyHash::Sha512(x) => {
                            let signing_key =
                                rrsa::pss::BlindedSigningKey::<Sha512>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(signing_key
                                .sign_digest_with_rng(&mut rng, x)
                                .to_bytes()
                                .into_vec())
                        }
                    }
                }
                Padding::PKCS1_OAEP => panic!("Invalid padding for signing"),
            }
        }
    }

    #[derive(Clone)]
    pub struct Verifier<'t, T> {
        pub message_digest: MessageDigest,
        pub pkey_ref: &'t PKey<T>,
        pub padding: Padding,
        pub salt_len: RsaPssSaltlen,
        pub any_hash: AnyHash,
    }

    impl<'t, T> Verifier<'t, T> {
        pub fn new(type_: MessageDigest, pkey: &'t PKey<T>) -> Result<Verifier<'t, T>, ErrorStack>
        where
            T: HasPublic,
        {
            let any_hash = match type_ {
                MessageDigest::Sha256 => AnyHash::Sha256(Sha256::new()),
                MessageDigest::Sha384 => AnyHash::Sha384(Sha384::new()),
                MessageDigest::Sha512 => AnyHash::Sha512(Sha512::new()),
            };
            Ok(Verifier {
                message_digest: type_,
                pkey_ref: pkey,
                padding: Padding::NONE,
                salt_len: RsaPssSaltlen::default(),
                any_hash,
            })
        }

        pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
            self.padding = padding;
            Ok(())
        }

        pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
            Ok(self.padding)
        }

        pub fn set_rsa_pss_saltlen(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
            self.salt_len = len;
            Ok(())
        }

        pub fn rsa_pss_saltlen(&self) -> Result<RsaPssSaltlen, ErrorStack> {
            Ok(self.salt_len)
        }

        pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
            match &mut self.any_hash {
                AnyHash::None => unreachable!("AnyHash::None"),
                AnyHash::Sha256(x) => x.update(buf),
                AnyHash::Sha384(x) => x.update(buf),
                AnyHash::Sha512(x) => x.update(buf),
            };
            Ok(())
        }

        pub fn verify(&self, signature: &[u8]) -> Result<bool, ErrorStack> {
            let rsa_key = if let PKey::Rsa(x) = self.pkey_ref {
                x
            } else {
                unreachable!();
            };
            let rsa_key = if let RsaKey::Public(x) = &rsa_key.rsa_key {
                x
            } else {
                unreachable!();
            };
            let rsa_key = rsa_key.clone();
            match self.padding {
                Padding::NONE => panic!("Padding not set"),
                Padding::PKCS1 => {
                    let rsa_signature = match rrsa::pkcs1v15::Signature::try_from(signature) {
                        Ok(x) => x,
                        Err(_) => return Ok(false),
                    };
                    match self.any_hash {
                        AnyHash::None => unreachable!("AnyHash::None"),
                        AnyHash::Sha256(x) => {
                            let verifying_key =
                                rrsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key);
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                        AnyHash::Sha384(x) => {
                            let verifying_key =
                                rrsa::pkcs1v15::VerifyingKey::<Sha384>::new(rsa_key);
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                        AnyHash::Sha512(x) => {
                            let verifying_key =
                                rrsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_key);
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                    }
                }
                Padding::PKCS1_PSS => {
                    let hash_len = match self.message_digest {
                        MessageDigest::Sha256 => 32,
                        MessageDigest::Sha384 => 48,
                        MessageDigest::Sha512 => 64,
                    };
                    let salt_len = match self.salt_len.len {
                        -1 => hash_len,
                        -2 => rsa_key.size() - hash_len - 2,
                        x => x as _,
                    };
                    let rsa_signature = match rrsa::pss::Signature::try_from(signature) {
                        Ok(x) => x,
                        Err(_) => return Ok(false),
                    };
                    match self.any_hash {
                        AnyHash::None => unreachable!("AnyHash::None"),
                        AnyHash::Sha256(x) => {
                            let verifying_key =
                                rrsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                        AnyHash::Sha384(x) => {
                            let verifying_key =
                                rrsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                        AnyHash::Sha512(x) => {
                            let verifying_key =
                                rrsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(
                                    rsa_key, salt_len,
                                );
                            Ok(verifying_key.verify_digest(x, &rsa_signature).is_ok())
                        }
                    }
                }
                Padding::PKCS1_OAEP => panic!("Invalid padding for verification"),
            }
        }

        pub fn verify_oneshot(&mut self, signature: &[u8], buf: &[u8]) -> Result<bool, ErrorStack> {
            self.update(buf)?;
            self.verify(signature)
        }
    }
}

#[allow(unused_imports)]
use symm::*;
pub mod symm {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Mode {
        Encrypt,
        Decrypt,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CipherType {
        Aes128Gcm,
        Aes256Gcm,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Cipher {
        cipher_type: CipherType,
    }

    impl Cipher {
        pub fn aes_128_gcm() -> Self {
            Cipher {
                cipher_type: CipherType::Aes128Gcm,
            }
        }

        pub fn aes_256_gcm() -> Self {
            Cipher {
                cipher_type: CipherType::Aes256Gcm,
            }
        }

        pub fn block_size(&self) -> usize {
            1
        }

        pub fn key_len(&self) -> usize {
            match self.cipher_type {
                CipherType::Aes128Gcm => 16,
                CipherType::Aes256Gcm => 32,
            }
        }

        pub fn iv_len(&self) -> Option<usize> {
            Some(12)
        }
    }

    enum AesGcmCipher {
        Aes128(Aes128Gcm),
        Aes256(Aes256Gcm),
    }

    pub struct Crypter {
        cipher: AesGcmCipher,
        mode: Mode,
        nonce: [u8; 12],
        aad: Vec<u8>,
        input_buf: Vec<u8>,
        tag: Option<[u8; 16]>,
        output_tag: Option<[u8; 16]>,
        output_ptr: Option<*mut u8>,
        output_len: usize,
    }

    impl Crypter {
        pub fn new(
            cipher: Cipher,
            mode: Mode,
            key: &[u8],
            iv: Option<&[u8]>,
        ) -> Result<Self, ErrorStack> {
            let iv = iv.ok_or(ErrorStack::KeyError)?;
            if iv.len() != 12 {
                return Err(ErrorStack::KeyError);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(iv);

            let aes_cipher = match cipher.cipher_type {
                CipherType::Aes128Gcm => {
                    if key.len() != 16 {
                        return Err(ErrorStack::KeyError);
                    }
                    let key_arr = GenericArray::from_slice(key);
                    AesGcmCipher::Aes128(Aes128Gcm::new(key_arr))
                }
                CipherType::Aes256Gcm => {
                    if key.len() != 32 {
                        return Err(ErrorStack::KeyError);
                    }
                    let key_arr = GenericArray::from_slice(key);
                    AesGcmCipher::Aes256(Aes256Gcm::new(key_arr))
                }
            };

            Ok(Crypter {
                cipher: aes_cipher,
                mode,
                nonce,
                aad: Vec::new(),
                input_buf: Vec::new(),
                tag: None,
                output_tag: None,
                output_ptr: None,
                output_len: 0,
            })
        }

        pub fn aad_update(&mut self, aad: &[u8]) -> Result<(), ErrorStack> {
            self.aad.extend_from_slice(aad);
            Ok(())
        }

        pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            let nonce = GenericArray::from_slice(&self.nonce);

            match self.mode {
                Mode::Encrypt => {
                    self.input_buf = input.to_vec();
                    let tag = match &self.cipher {
                        AesGcmCipher::Aes128(c) => c
                            .encrypt_in_place_detached(nonce, &self.aad, &mut self.input_buf)
                            .map_err(|_| ErrorStack::KeyError)?,
                        AesGcmCipher::Aes256(c) => c
                            .encrypt_in_place_detached(nonce, &self.aad, &mut self.input_buf)
                            .map_err(|_| ErrorStack::KeyError)?,
                    };
                    output[..self.input_buf.len()].copy_from_slice(&self.input_buf);
                    let mut tag_arr = [0u8; 16];
                    tag_arr.copy_from_slice(&tag);
                    self.output_tag = Some(tag_arr);
                }
                Mode::Decrypt => {
                    self.input_buf = input.to_vec();
                    self.output_ptr = Some(output.as_mut_ptr());
                    self.output_len = output.len().min(input.len());
                }
            }
            Ok(input.len())
        }

        pub fn finalize(&mut self, _output: &mut [u8]) -> Result<usize, ErrorStack> {
            if self.mode == Mode::Decrypt {
                let nonce = GenericArray::from_slice(&self.nonce);
                let tag = self.tag.ok_or(ErrorStack::KeyError)?;
                let tag = GenericArray::from_slice(&tag);
                match &self.cipher {
                    AesGcmCipher::Aes128(c) => c
                        .decrypt_in_place_detached(nonce, &self.aad, &mut self.input_buf, tag)
                        .map_err(|_| ErrorStack::KeyError)?,
                    AesGcmCipher::Aes256(c) => c
                        .decrypt_in_place_detached(nonce, &self.aad, &mut self.input_buf, tag)
                        .map_err(|_| ErrorStack::KeyError)?,
                };
                if let Some(ptr) = self.output_ptr {
                    let copy_len = self.output_len.min(self.input_buf.len());
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.input_buf.as_ptr(),
                            ptr,
                            copy_len,
                        );
                    }
                }
            }
            Ok(0)
        }

        pub fn get_tag(&self, tag: &mut [u8]) -> Result<(), ErrorStack> {
            let output_tag = self.output_tag.ok_or(ErrorStack::KeyError)?;
            if tag.len() < 16 {
                return Err(ErrorStack::Overflow);
            }
            tag[..16].copy_from_slice(&output_tag);
            Ok(())
        }

        pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), ErrorStack> {
            if tag.len() != 16 {
                return Err(ErrorStack::KeyError);
            }
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(tag);
            self.tag = Some(tag_arr);
            Ok(())
        }
    }
}

#[test]
fn test_rsa_pkcs1() {
    let sk = Rsa::generate(2048).unwrap();
    let pk = sk.public_key().unwrap();

    let sk = PKey::from_rsa(sk).unwrap();
    let pk = PKey::from_rsa(pk).unwrap();

    let mut signer = Signer::new(MessageDigest::Sha256, &sk).unwrap();
    let mut verifier = Verifier::new(MessageDigest::Sha256, &pk).unwrap();

    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1).unwrap();

    signer.update(b"hello").unwrap();
    let signature = signer.sign_to_vec().unwrap();

    verifier.update(b"hello").unwrap();
    let res = verifier.verify(&signature).unwrap();
    assert!(res);
}

#[test]
fn test_rsa_pss() {
    let sk = Rsa::generate(2048).unwrap();
    let pk = sk.public_key().unwrap();

    let sk = PKey::from_rsa(sk).unwrap();
    let pk = PKey::from_rsa(pk).unwrap();

    let mut signer = Signer::new(MessageDigest::Sha384, &sk).unwrap();
    let mut verifier = Verifier::new(MessageDigest::Sha384, &pk).unwrap();

    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

    signer.update(b"hello").unwrap();
    let signature = signer.sign_to_vec().unwrap();

    verifier.update(b"hello").unwrap();
    let res = verifier.verify(&signature).unwrap();
    assert!(res);
}

#[test]
fn test_rsa_encrypt_decrypt() {
    let sk = Rsa::generate(2048).unwrap();
    let pk = sk.public_key().unwrap();

    let mut ciphertext = [0u8; 256];
    let mut recovered_plaintext = [0u8; 256];

    let len = pk
        .public_encrypt(b"hello", &mut ciphertext, Padding::PKCS1)
        .unwrap();
    let len2 = sk
        .private_decrypt(
            &ciphertext[0..len],
            &mut recovered_plaintext,
            Padding::PKCS1,
        )
        .unwrap();

    assert_eq!(&recovered_plaintext[0..len2], b"hello");
}

#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    let sk = Rsa::generate(2048).unwrap();
    let pk = sk.public_key().unwrap();

    let mut ciphertext = [0u8; 256];
    let mut recovered_plaintext = [0u8; 256];

    let len = pk
        .public_encrypt(b"hello oaep", &mut ciphertext, Padding::PKCS1_OAEP)
        .unwrap();
    let len2 = sk
        .private_decrypt(
            &ciphertext[0..len],
            &mut recovered_plaintext,
            Padding::PKCS1_OAEP,
        )
        .unwrap();

    assert_eq!(&recovered_plaintext[0..len2], b"hello oaep");
}

#[test]
fn test_aes_keywrap_128() {
    use aes::{wrap_key, unwrap_key, AesKey};

    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let key_data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let expected = [
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B,
        0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    ];

    let enc_key = AesKey::new_encrypt(&kek).unwrap();
    let mut ciphertext = [0u8; 24];
    let len = wrap_key(&enc_key, None, &mut ciphertext, &key_data).unwrap();
    assert_eq!(len, 24);
    assert_eq!(ciphertext, expected);

    let dec_key = AesKey::new_decrypt(&kek).unwrap();
    let mut plaintext = [0u8; 16];
    let len = unwrap_key(&dec_key, None, &mut plaintext, &ciphertext).unwrap();
    assert_eq!(len, 16);
    assert_eq!(plaintext, key_data);
}

#[test]
fn test_aes_keywrap_256() {
    use aes::{wrap_key, unwrap_key, AesKey};

    let kek = [0x42u8; 32];
    let key_data = b"1234567812345678";

    let enc_key = AesKey::new_encrypt(&kek).unwrap();
    let mut ciphertext = [0u8; 24];
    let len = wrap_key(&enc_key, None, &mut ciphertext, key_data).unwrap();
    assert_eq!(len, 24);

    let dec_key = AesKey::new_decrypt(&kek).unwrap();
    let mut plaintext = [0u8; 16];
    let len = unwrap_key(&dec_key, None, &mut plaintext, &ciphertext).unwrap();
    assert_eq!(len, 16);
    assert_eq!(&plaintext, key_data);
}
