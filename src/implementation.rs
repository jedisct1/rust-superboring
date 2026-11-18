use hmac_sha1_compact::WrappedHash011 as Sha1;
use hmac_sha256::Hash as Sha256;
use hmac_sha512::sha384::Hash as Sha384;
use hmac_sha512::Hash as Sha512;
use std::ffi::c_int;

use hmac_sha256::HMAC as HmacSha256;
use hmac_sha512::sha384::HMAC as HmacSha384;
use hmac_sha512::HMAC as HmacSha512;

use rrsa::pkcs1::EncodeRsaPrivateKey as _;
use rrsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};

#[cfg(all(
    feature = "wasi-crypto",
    target_arch = "wasm32",
    target_os = "wasi",
    target_env = "p1"
))]
mod wasi_crypto {
    use rrsa::pkcs1::DecodeRsaPrivateKey as _;
    use rrsa::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
    use wasi_crypto_guest::error::Error as WasiCryptoError;
    use wasi_crypto_guest::signatures::{Signature, SignatureKeyPair, SignaturePublicKey};
    use wasi_crypto_guest::symmetric::{AeadKey, Auth, AuthKey, SymmetricOptions, SymmetricState};

    use super::*;

    pub type WasiAeadKey = AeadKey;
    pub type WasiAuth = Auth;

    fn is_required_rsa_signature_algorithm(alg: &str) -> bool {
        matches!(
            alg,
            "RSA_PKCS1_2048_SHA256" | "RSA_PKCS1_3072_SHA384" | "RSA_PKCS1_4096_SHA512"
        )
    }

    fn operation_may_fallback(error: WasiCryptoError) -> bool {
        matches!(
            error,
            WasiCryptoError::NotImplemented
                | WasiCryptoError::UnsupportedEncoding
                | WasiCryptoError::UnsupportedFeature
                | WasiCryptoError::UnsupportedOption
        )
    }

    fn rsa_may_fallback(alg: &str, error: WasiCryptoError) -> bool {
        operation_may_fallback(error)
            || (!is_required_rsa_signature_algorithm(alg)
                && matches!(error, WasiCryptoError::UnsupportedAlgorithm))
    }

    fn map_error(error: WasiCryptoError) -> ErrorStack {
        match error {
            WasiCryptoError::InvalidKey
            | WasiCryptoError::InvalidLength
            | WasiCryptoError::InvalidOperation
            | WasiCryptoError::InvalidTag
            | WasiCryptoError::InvalidNonce
            | WasiCryptoError::KeyRequired
            | WasiCryptoError::KeyNotSupported
            | WasiCryptoError::UnsupportedAlgorithm
            | WasiCryptoError::UnsupportedEncoding
            | WasiCryptoError::UnsupportedFeature
            | WasiCryptoError::UnsupportedOption => ErrorStack::KeyError,
            WasiCryptoError::Overflow => ErrorStack::Overflow,
            _ => ErrorStack::InternalError,
        }
    }

    pub fn auth_new(alg: &'static str, key: &[u8]) -> Result<WasiAuth, ErrorStack> {
        let key = match AuthKey::from_raw(alg, key) {
            Ok(key) => key,
            Err(error) => return Err(map_error(error)),
        };
        match Auth::new(&key) {
            Ok(auth) => Ok(auth),
            Err(error) => Err(map_error(error)),
        }
    }

    pub fn auth_absorb(auth: &mut WasiAuth, data: &[u8]) -> Result<(), ErrorStack> {
        match auth.absorb(data) {
            Ok(()) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    pub fn auth_tag(auth: &mut WasiAuth) -> Result<Vec<u8>, ErrorStack> {
        match auth.tag() {
            Ok(tag) => Ok(tag),
            Err(error) => Err(map_error(error)),
        }
    }

    pub fn hmac_alg(md: &MessageDigest) -> Option<&'static str> {
        match md {
            MessageDigest::Sha256 => Some("HMAC/SHA-256"),
            MessageDigest::Sha384 => None,
            MessageDigest::Sha512 => Some("HMAC/SHA-512"),
        }
    }

    pub fn aead_key(alg: &'static str, key: &[u8]) -> Result<WasiAeadKey, ErrorStack> {
        match AeadKey::from_raw(alg, key) {
            Ok(key) => Ok(key),
            Err(error) => Err(map_error(error)),
        }
    }

    fn aead_state(
        key: &WasiAeadKey,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<SymmetricState, ErrorStack> {
        let mut options = SymmetricOptions::new();
        options.set("nonce", nonce).map_err(map_error)?;
        let mut state = match SymmetricState::new(key.alg, Some(key), Some(&options)) {
            Ok(state) => state,
            Err(error) => return Err(map_error(error)),
        };
        match state.absorb(aad) {
            Ok(()) => Ok(state),
            Err(error) => Err(map_error(error)),
        }
    }

    pub fn aead_encrypt_detached(
        key: &WasiAeadKey,
        nonce: &[u8; 12],
        aad: &[u8],
        out: &mut [u8],
        plaintext: &[u8],
    ) -> Result<[u8; 16], ErrorStack> {
        let mut state = aead_state(key, nonce, aad)?;
        let tag = match state.encrypt_detached(out, plaintext) {
            Ok(tag) => tag,
            Err(error) => return Err(map_error(error)),
        };
        let tag: [u8; 16] = tag.try_into().map_err(|_| ErrorStack::KeyError)?;
        Ok(tag)
    }

    pub fn aead_decrypt_detached(
        key: &WasiAeadKey,
        nonce: &[u8; 12],
        aad: &[u8],
        out: &mut [u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), ErrorStack> {
        let mut state = aead_state(key, nonce, aad)?;
        match state.decrypt_detached(out, ciphertext, tag) {
            Ok(()) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    fn rsa_generate_alg(bits: u32) -> Option<&'static str> {
        match bits {
            2048 => Some("RSA_PKCS1_2048_SHA256"),
            3072 => Some("RSA_PKCS1_3072_SHA384"),
            4096 => Some("RSA_PKCS1_4096_SHA512"),
            _ => None,
        }
    }

    fn rsa_signature_alg(
        bits: usize,
        padding: Padding,
        md: &MessageDigest,
        mgf1_md: &MessageDigest,
        salt_len: RsaPssSaltlen,
    ) -> Option<&'static str> {
        if mgf1_md != md {
            return None;
        }
        let prefix = match padding {
            Padding::PKCS1 => "RSA_PKCS1",
            Padding::PKCS1_PSS if salt_len.len == RsaPssSaltlen::DIGEST_LENGTH.len => "RSA_PSS",
            _ => return None,
        };
        match (prefix, bits, md) {
            ("RSA_PKCS1", 2048, MessageDigest::Sha256) => Some("RSA_PKCS1_2048_SHA256"),
            ("RSA_PKCS1", 2048, MessageDigest::Sha384) => Some("RSA_PKCS1_2048_SHA384"),
            ("RSA_PKCS1", 2048, MessageDigest::Sha512) => Some("RSA_PKCS1_2048_SHA512"),
            ("RSA_PKCS1", 3072, MessageDigest::Sha384) => Some("RSA_PKCS1_3072_SHA384"),
            ("RSA_PKCS1", 3072, MessageDigest::Sha512) => Some("RSA_PKCS1_3072_SHA512"),
            ("RSA_PKCS1", 4096, MessageDigest::Sha512) => Some("RSA_PKCS1_4096_SHA512"),
            ("RSA_PSS", 2048, MessageDigest::Sha256) => Some("RSA_PSS_2048_SHA256"),
            ("RSA_PSS", 2048, MessageDigest::Sha384) => Some("RSA_PSS_2048_SHA384"),
            ("RSA_PSS", 2048, MessageDigest::Sha512) => Some("RSA_PSS_2048_SHA512"),
            ("RSA_PSS", 3072, MessageDigest::Sha384) => Some("RSA_PSS_3072_SHA384"),
            ("RSA_PSS", 3072, MessageDigest::Sha512) => Some("RSA_PSS_3072_SHA512"),
            ("RSA_PSS", 4096, MessageDigest::Sha512) => Some("RSA_PSS_4096_SHA512"),
            _ => None,
        }
    }

    pub fn rsa_generate(bits: u32) -> Result<Option<rrsa::PrivateKey>, ErrorStack> {
        let Some(alg) = rsa_generate_alg(bits) else {
            return Ok(None);
        };
        let keypair = match SignatureKeyPair::generate(alg) {
            Ok(keypair) => keypair,
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        let der = match keypair.pkcs8() {
            Ok(der) => der,
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        let mut rsa_key = rrsa::PrivateKey::from_pkcs8_der(&der)
            .or_else(|_| rrsa::PrivateKey::from_pkcs1_der(&der))
            .map_err(|_| ErrorStack::InvalidPrivateKey)?;
        rsa_key
            .precompute()
            .map_err(|_| ErrorStack::InvalidPrivateKey)?;
        Ok(Some(rsa_key))
    }

    pub fn rsa_sign(
        rsa_key: &rrsa::PrivateKey,
        padding: Padding,
        md: &MessageDigest,
        mgf1_md: &MessageDigest,
        salt_len: RsaPssSaltlen,
        msg: &[u8],
    ) -> Result<Option<Vec<u8>>, ErrorStack> {
        let Some(alg) = rsa_signature_alg(rsa_key.size() * 8, padding, md, mgf1_md, salt_len)
        else {
            return Ok(None);
        };
        let der = match rsa_key.to_pkcs8_der() {
            Ok(der) => der.as_bytes().to_vec(),
            Err(_) => return Err(ErrorStack::InvalidPrivateKey),
        };
        let keypair = match SignatureKeyPair::from_pkcs8(alg, der) {
            Ok(keypair) => keypair,
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        let signature = match keypair.sign(msg) {
            Ok(signature) => signature,
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        match signature.raw() {
            Ok(raw) => Ok(Some(raw)),
            Err(error) if rsa_may_fallback(alg, error) => Ok(None),
            Err(error) => Err(map_error(error)),
        }
    }

    pub fn rsa_verify(
        rsa_key: &rrsa::PublicKey,
        padding: Padding,
        md: &MessageDigest,
        mgf1_md: &MessageDigest,
        salt_len: RsaPssSaltlen,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<Option<bool>, ErrorStack> {
        let Some(alg) = rsa_signature_alg(rsa_key.size() * 8, padding, md, mgf1_md, salt_len)
        else {
            return Ok(None);
        };
        let der = match rsa_key.to_public_key_der() {
            Ok(der) => der.into_vec(),
            Err(_) => return Err(ErrorStack::InvalidPublicKey),
        };
        let public_key = match SignaturePublicKey::from_pkcs8(alg, der) {
            Ok(public_key) => public_key,
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        let signature = match Signature::from_raw(alg, signature) {
            Ok(signature) => signature,
            Err(WasiCryptoError::InvalidSignature) => return Ok(Some(false)),
            Err(error) if rsa_may_fallback(alg, error) => return Ok(None),
            Err(error) => return Err(map_error(error)),
        };
        match public_key.signature_verify(msg, &signature) {
            Ok(()) => Ok(Some(true)),
            Err(WasiCryptoError::VerificationFailed | WasiCryptoError::InvalidSignature) => {
                Ok(Some(false))
            }
            Err(error) if rsa_may_fallback(alg, error) => Ok(None),
            Err(error) => Err(map_error(error)),
        }
    }
}

pub mod reexports {
    pub use hmac_sha256;
    pub use hmac_sha512;
    pub use ml_dsa;
    pub use rand;
    pub use rrsa as rsa;
}

#[allow(unused_imports)]
use rsa::*;
pub mod rsa {
    #[allow(unused_imports)]
    use super::*;

    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, PartialEq, Eq, Default)]
    pub enum RsaKey {
        #[default]
        None,
        Public(rrsa::PublicKey),
        Private(rrsa::PrivateKey),
        Invalid(Box<InvalidKey>),
    }

    /// A key built from components that BoringSSL wouldn't use.
    ///
    /// BoringSSL accepts any components and only complains when the key is checked or used, so we keep them as they were given.
    #[derive(Clone, PartialEq, Eq)]
    pub struct InvalidKey {
        n: BigNum,
        e: BigNum,
        private: Option<PrivateParts>,
        /// Set when BoringSSL could still use the key anyway.
        usable: Option<rrsa::PrivateKey>,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct PrivateParts {
        d: BigNum,
        p: BigNum,
        q: BigNum,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    }

    impl std::fmt::Debug for RsaKey {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                RsaKey::None => write!(f, "RsaKey::None"),
                RsaKey::Public(_) => write!(f, "RsaKey::Public"),
                RsaKey::Private(_) => write!(f, "RsaKey::Private"),
                RsaKey::Invalid(_) => write!(f, "RsaKey::Invalid"),
            }
        }
    }

    fn bn(x: &rrsa::BoxedUint) -> BigNum {
        BigNum { rsa_bn: x.clone() }
    }

    impl RsaKey {
        fn n(&self) -> BigNum {
            match self {
                RsaKey::Public(x) => bn(x.n().as_ref()),
                RsaKey::Private(x) => bn(x.n().as_ref()),
                RsaKey::Invalid(x) => x.n.clone(),
                RsaKey::None => unreachable!(),
            }
        }

        fn e(&self) -> BigNum {
            match self {
                RsaKey::Public(x) => bn(x.e()),
                RsaKey::Private(x) => bn(x.e()),
                RsaKey::Invalid(x) => x.e.clone(),
                RsaKey::None => unreachable!(),
            }
        }

        pub(crate) fn size(&self) -> usize {
            match self {
                RsaKey::Public(x) => x.size(),
                RsaKey::Private(x) => x.size(),
                RsaKey::Invalid(x) => x.n.num_bytes() as usize,
                RsaKey::None => unreachable!(),
            }
        }

        pub(crate) fn public_key(&self) -> Option<&rrsa::PublicKey> {
            match self {
                RsaKey::Public(x) => Some(x),
                RsaKey::Private(x) => Some(x.as_public_key()),
                _ => None,
            }
        }

        pub(crate) fn private_key(&self) -> Option<&rrsa::PrivateKey> {
            match self {
                RsaKey::Private(x) => Some(x),
                RsaKey::Invalid(x) => x.usable.as_ref(),
                _ => None,
            }
        }

        fn invalid_private(&self) -> &PrivateParts {
            match self {
                RsaKey::Invalid(x) => x.private.as_ref().expect("a private key"),
                _ => unreachable!(),
            }
        }
    }

    fn to_pem(label: &str, der: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        use rrsa::pkcs1::der::pem::{encode_string, LineEnding};

        encode_string(label, LineEnding::LF, der)
            .map(String::into_bytes)
            .map_err(|_| ErrorStack::InvalidPublicKey)
    }

    // Keys are serialized from their components, so invalid ones come out as they were given, like with BoringSSL.

    fn public_key_der_pkcs1(n: &BigNum, e: &BigNum) -> Result<Vec<u8>, ErrorStack> {
        use rrsa::pkcs1::der::Encode;

        let (n, e) = (n.rsa_bn.to_be_bytes(), e.rsa_bn.to_be_bytes());
        let uint_ref = |x| rrsa::pkcs1::UintRef::new(x).map_err(|_| ErrorStack::InvalidPublicKey);
        rrsa::pkcs1::RsaPublicKeyRef {
            modulus: uint_ref(&n)?,
            public_exponent: uint_ref(&e)?,
        }
        .to_der()
        .map_err(|_| ErrorStack::InvalidPublicKey)
    }

    fn public_key_der(n: &BigNum, e: &BigNum) -> Result<Vec<u8>, ErrorStack> {
        use rrsa::pkcs1::der::asn1::BitStringRef;
        use rrsa::pkcs1::der::Encode;

        let key = public_key_der_pkcs1(n, e)?;
        rrsa::pkcs8::SubjectPublicKeyInfoRef {
            algorithm: rrsa::pkcs1::ALGORITHM_ID,
            subject_public_key: BitStringRef::from_bytes(&key)
                .map_err(|_| ErrorStack::InvalidPublicKey)?,
        }
        .to_der()
        .map_err(|_| ErrorStack::InvalidPublicKey)
    }

    fn private_key_der(
        n: &BigNum,
        e: &BigNum,
        private: &PrivateParts,
    ) -> Result<Vec<u8>, ErrorStack> {
        use rrsa::pkcs1::der::Encode;

        let values = [
            n,
            e,
            &private.d,
            &private.p,
            &private.q,
            &private.dmp1,
            &private.dmq1,
            &private.iqmp,
        ]
        .map(|x| x.rsa_bn.to_be_bytes());
        let uint_ref = |i: usize| {
            rrsa::pkcs1::UintRef::new(&values[i]).map_err(|_| ErrorStack::InvalidPrivateKey)
        };
        rrsa::pkcs1::RsaPrivateKeyRef {
            modulus: uint_ref(0)?,
            public_exponent: uint_ref(1)?,
            private_exponent: uint_ref(2)?,
            prime1: uint_ref(3)?,
            prime2: uint_ref(4)?,
            exponent1: uint_ref(5)?,
            exponent2: uint_ref(6)?,
            coefficient: uint_ref(7)?,
            other_prime_infos: None,
        }
        .to_der()
        .map_err(|_| ErrorStack::InvalidPrivateKey)
    }

    fn crt_values_match(rsa_key: &rrsa::PrivateKey, private: &PrivateParts) -> bool {
        rsa_key.dp() == Some(&private.dmp1.rsa_bn)
            && rsa_key.dq() == Some(&private.dmq1.rsa_bn)
            && rsa_key.qinv().map(|x| x.retrieve()).as_ref() == Some(&private.iqmp.rsa_bn)
    }

    #[derive(Clone, Default, PartialEq, Eq)]
    pub struct Rsa<T> {
        pub rsa_key: RsaKey,
        pub _marker: std::marker::PhantomData<T>,
    }

    impl<T> std::fmt::Debug for Rsa<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Rsa")
        }
    }

    impl<T> Rsa<T> {
        fn from_key(rsa_key: RsaKey) -> Self {
            Rsa {
                rsa_key,
                _marker: std::marker::PhantomData,
            }
        }

        pub fn size(&self) -> u32 {
            self.rsa_key.size() as u32
        }

        pub fn bits(&self) -> u32 {
            self.n().num_bits() as u32
        }

        pub fn n(&self) -> BigNum {
            self.rsa_key.n()
        }

        pub fn e(&self) -> BigNum {
            self.rsa_key.e()
        }
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

    // What BoringSSL accepts. The rsa crate defaults to 1024 to 8192 bits.
    const MODULUS_BITS: std::ops::RangeInclusive<usize> = 512..=16384;

    fn public_parameters_are_valid(n: &rrsa::BoxedUint, e: &rrsa::BoxedUint) -> bool {
        MODULUS_BITS.contains(&(n.bit_width_vartime() as usize))
            && n.as_uint_ref().is_odd().to_bool()
            && e.as_uint_ref().is_odd().to_bool()
            && *e > rrsa::BoxedUint::one()
            && e.bit_width_vartime() <= 33
            && e < n
    }

    fn new_public_key(n: BigNum, e: BigNum) -> Result<rrsa::PublicKey, ErrorStack> {
        rrsa::PublicKey::new_with_size_limits(n.rsa_bn, e.rsa_bn, MODULUS_BITS)
            .map_err(|_| ErrorStack::InvalidPublicKey)
    }

    // The rsa crate's own decoders would use its default size limits.
    fn public_key_from_pkcs1_der(der: &[u8]) -> Result<rrsa::PublicKey, ErrorStack> {
        let key = rrsa::pkcs1::RsaPublicKeyRef::try_from(der)
            .map_err(|_| ErrorStack::InvalidPublicKey)?;
        new_public_key(
            BigNum::from_slice(key.modulus.as_bytes())?,
            BigNum::from_slice(key.public_exponent.as_bytes())?,
        )
    }

    fn public_key_from_spki_der(der: &[u8]) -> Result<rrsa::PublicKey, ErrorStack> {
        let spki = rrsa::pkcs8::SubjectPublicKeyInfoRef::try_from(der)
            .map_err(|_| ErrorStack::InvalidPublicKey)?;
        if spki.algorithm != rrsa::pkcs1::ALGORITHM_ID {
            return Err(ErrorStack::InvalidPublicKey);
        }
        let key = spki
            .subject_public_key
            .as_bytes()
            .ok_or(ErrorStack::InvalidPublicKey)?;
        public_key_from_pkcs1_der(key)
    }

    /// Like BoringSSL's `d2i_*()` functions, anything after the first DER element is ignored.
    fn first_der_element(der: &[u8]) -> Option<&[u8]> {
        use rrsa::pkcs1::der::{Reader, SliceReader};

        SliceReader::new(der).ok()?.tlv_bytes().ok()
    }

    /// BoringSSL rejects attributes that aren't an OID followed by a set of values.
    fn check_attributes(attributes: &[u8]) -> rrsa::pkcs1::der::Result<()> {
        use rrsa::pkcs1::der::asn1::AnyRef;
        use rrsa::pkcs1::der::{Decode, Header, Reader, SliceReader, Tag};

        // Same check as BoringSSL's `CBS_is_valid_asn1_oid()`.
        let valid_oid = |oid: &[u8]| {
            let mut prev = 0u8;
            for &x in oid {
                if prev & 0x80 == 0 && x == 0x80 {
                    return false;
                }
                prev = x;
            }
            !oid.is_empty() && prev & 0x80 == 0
        };
        let mut reader = SliceReader::new(attributes)?;
        while !reader.is_finished() {
            reader.sequence(|attribute| -> rrsa::pkcs1::der::Result<()> {
                let header = Header::decode(attribute)?;
                header.tag().assert_eq(Tag::ObjectIdentifier)?;
                if !valid_oid(attribute.read_slice(header.length())?) {
                    return Err(Tag::ObjectIdentifier.value_error().into());
                }
                let header = Header::decode(attribute)?;
                header.tag().assert_eq(Tag::Set)?;
                attribute.read_nested(header.length(), |values| {
                    while !values.is_finished() {
                        AnyRef::decode(values)?;
                    }
                    Ok(())
                })
            })?;
        }
        Ok(())
    }

    /// Returns the PKCS#1 key inside a PKCS#8 structure.
    ///
    /// BoringSSL has two parsers for this: a strict one that only allows attributes after the key, and one that ignores whatever comes after it.
    fn pkcs8_rsa_private_key(der: &[u8], strict: bool) -> Option<&[u8]> {
        use rrsa::pkcs1::der::asn1::OctetStringRef;
        use rrsa::pkcs1::der::{Decode, Header, Reader, SliceReader, Tag, TagNumber};

        let mut reader = SliceReader::new(der).ok()?;
        let (algorithm, key) = reader
            .sequence(|seq| -> rrsa::pkcs1::der::Result<_> {
                if u8::decode(seq)? != 0 {
                    return Err(Tag::Integer.value_error().into());
                }
                let algorithm = rrsa::pkcs8::AlgorithmIdentifierRef::decode(seq)?;
                let key = <&OctetStringRef>::decode(seq)?;
                if !strict {
                    seq.read_slice(seq.remaining_len())?;
                } else if !seq.is_finished() {
                    // Anything after the attributes is an error, which the decoder takes care of.
                    let attributes = Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber(0),
                    };
                    let header = Header::decode(seq)?;
                    if header.tag() != attributes {
                        return Err(header.tag().value_error().into());
                    }
                    check_attributes(seq.read_slice(header.length())?)?;
                }
                Ok((algorithm, key))
            })
            .ok()?;
        (algorithm == rrsa::pkcs1::ALGORITHM_ID).then_some(key.as_bytes())
    }

    /// A port of BoringSSL's PEM reader, which is much more forgiving than the standard.
    ///
    /// It ignores text around the blocks, skips blocks with other labels, and doesn't care about line lengths.
    mod pem {
        struct Lines<'a>(&'a [u8]);

        impl Lines<'_> {
            /// Reads a line the way BoringSSL does: at most 253 bytes at a time, with trailing whitespace and control characters replaced by a newline.
            ///
            /// Bytes above 0x7f count as control characters too, because `char` is signed in C.
            fn next(&mut self) -> Option<Vec<u8>> {
                const MAX_LEN: usize = 253;

                if self.0.is_empty() {
                    return None;
                }
                let len = match self.0.iter().take(MAX_LEN).position(|&c| c == b'\n') {
                    Some(i) => i + 1,
                    None => self.0.len().min(MAX_LEN),
                };
                let (line, rest) = self.0.split_at(len);
                self.0 = rest;
                let mut line = line.to_vec();
                while line.last().is_some_and(|&c| c as i8 <= b' ' as i8) {
                    line.pop();
                }
                line.push(b'\n');
                Some(line)
            }
        }

        /// What C string functions see of a line.
        fn c_str(line: &[u8]) -> &[u8] {
            &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())]
        }

        /// Collects lines until the END line, or until a blank line if `stop_at_blank_line` is set, in which case it returns `true`.
        /// `last` ends up holding the last line read.
        fn read_until_end(
            lines: &mut Lines,
            last: &mut Vec<u8>,
            out: &mut Vec<u8>,
            stop_at_blank_line: bool,
        ) -> bool {
            while let Some(line) = lines.next() {
                *last = line;
                if stop_at_blank_line && last.as_slice() == b"\n" {
                    return true;
                }
                if c_str(last).starts_with(b"-----END ") {
                    return false;
                }
                out.extend_from_slice(last);
            }
            last.clear();
            false
        }

        /// BoringSSL's base64 decoder, which skips whitespace.
        fn decode_base64(encoded: &[u8]) -> Option<Vec<u8>> {
            let value = |c: u8| match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(0),
                _ => None,
            };
            let mut out = Vec::with_capacity(encoded.len() / 4 * 3);
            let (mut quad, mut used, mut eof) = ([0u8; 4], 0, false);
            for &c in encoded {
                if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
                    continue;
                }
                if eof {
                    return None;
                }
                quad[used] = c;
                used += 1;
                if used < 4 {
                    continue;
                }
                used = 0;
                let v = quad
                    .iter()
                    .try_fold(0u32, |acc, &c| Some(acc << 6 | value(c)? as u32))?;
                let len = match quad.map(|c| c == b'=') {
                    [false, false, false, false] => 3,
                    [false, false, false, true] => 2,
                    [false, false, true, true] => 1,
                    _ => return None,
                };
                out.extend_from_slice(&v.to_be_bytes()[1..1 + len]);
                eof = len < 3;
            }
            (used == 0).then_some(out)
        }

        struct Block {
            label: Vec<u8>,
            header: Vec<u8>,
            data: Vec<u8>,
        }

        /// Reads the next PEM block, like `PEM_read_bio_inner()`.
        fn read_block(lines: &mut Lines) -> Option<Block> {
            let label = loop {
                let line = lines.next()?;
                let label = c_str(&line)
                    .strip_prefix(b"-----BEGIN ")
                    .and_then(|rest| rest.strip_suffix(b"-----\n"));
                if let Some(label) = label {
                    break label.to_vec();
                }
            };
            let (mut last, mut header, mut data) = (Vec::new(), Vec::new(), Vec::new());
            if read_until_end(lines, &mut last, &mut header, true) {
                read_until_end(lines, &mut last, &mut data, false);
            } else {
                // There was no header, so that was the body.
                std::mem::swap(&mut header, &mut data);
            }
            if c_str(&last) != [b"-----END ".as_slice(), &label, b"-----\n"].concat() {
                return None;
            }
            let data = decode_base64(&data)?;
            (!data.is_empty()).then_some(Block {
                label,
                header,
                data,
            })
        }

        /// Returns the label and contents of the first block with a label we want, like `PEM_bytes_read_bio()`.
        pub(super) fn read(
            pem: &[u8],
            accept: impl Fn(&[u8]) -> bool,
        ) -> Option<(Vec<u8>, Vec<u8>)> {
            let mut lines = Lines(pem);
            loop {
                let block = read_block(&mut lines)?;
                if accept(&block.label) {
                    // Headers only come with encrypted keys, and we never have a password.
                    return block.header.is_empty().then_some((block.label, block.data));
                }
            }
        }
    }

    fn pem_der(pem: &[u8], label: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        pem::read(pem, |x| x == label)
            .map(|(_, der)| der)
            .ok_or(ErrorStack::InvalidPublicKey)
    }

    fn i2osp(x: &rrsa::BoxedUint, k: usize) -> Vec<u8> {
        let bytes = x.to_be_bytes();
        let mut out = vec![0u8; k.saturating_sub(bytes.len())];
        out.extend_from_slice(&bytes[bytes.len().saturating_sub(k)..]);
        out
    }

    fn os2ip(input: &[u8], key: &impl rrsa::traits::PublicKeyParts) -> Option<rrsa::BoxedUint> {
        if input.len() != key.size() {
            return None;
        }
        let x = rrsa::BoxedUint::from_be_slice(input, key.n_bits_precision()).ok()?;
        (x < *key.n().as_ref()).then_some(x)
    }

    /// Raw RSA with the public key, on input as long as the modulus and smaller than it.
    pub(crate) fn raw_public_op(
        rsa_key: &rrsa::PublicKey,
        input: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        let m = os2ip(input, rsa_key).ok_or(ErrorStack::InvalidPublicKey)?;
        let c = rrsa::hazmat::rsa_encrypt(rsa_key, &m).map_err(|_| ErrorStack::InvalidPublicKey)?;
        Ok(i2osp(&c, rsa_key.size()))
    }

    /// Raw RSA with the private key, with blinding and a check against faults.
    pub(crate) fn raw_private_op(
        rsa_key: &rrsa::PrivateKey,
        input: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        let c = os2ip(input, rsa_key).ok_or(ErrorStack::InvalidPrivateKey)?;
        let m = rrsa::hazmat::rsa_decrypt_and_check(rsa_key, Some(&mut rand::rng()), &c)
            .map_err(|_| ErrorStack::InvalidPrivateKey)?;
        Ok(i2osp(&m, rsa_key.size()))
    }

    /// PKCS#1 v1.5 decryption that returns an error on bad padding, like BoringSSL.
    ///
    /// The rsa crate only returns a fake message in that case.
    fn pkcs1v15_decrypt(
        rsa_key: &rrsa::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        if rsa_key.size() < 11 {
            return Err(ErrorStack::InvalidPrivateKey);
        }
        let mut em = raw_private_op(rsa_key, ciphertext)?;
        let result = pkcs1v15_unpad(&em);
        em.fill(0);
        std::hint::black_box(&em);
        result
    }

    fn pkcs1v15_unpad(em: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        use std::hint::black_box;

        let msb = |a: usize| 0usize.wrapping_sub(a >> (usize::BITS - 1));
        let is_zero = |a: usize| msb(!a & a.wrapping_sub(1));
        let lt = |a: usize, b: usize| msb(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ a)));
        let select =
            |mask: usize, a: usize, b: usize| (black_box(mask) & a) | (black_box(!mask) & b);

        let first_byte_is_zero = is_zero(em[0] as usize);
        let second_byte_is_two = is_zero(em[1] as usize ^ 2);
        let mut zero_index = 0;
        let mut looking_for_index = usize::MAX;
        for (i, &byte) in em.iter().enumerate().skip(2) {
            let equals0 = is_zero(byte as usize);
            zero_index = select(looking_for_index & equals0, i, zero_index);
            looking_for_index = select(equals0, 0, looking_for_index);
        }
        // 00 02, then at least 8 nonzero padding bytes, then a zero separator.
        let valid =
            first_byte_is_zero & second_byte_is_two & !looking_for_index & !lt(zero_index, 2 + 8);
        if black_box(valid) == 0 {
            return Err(ErrorStack::InvalidPrivateKey);
        }
        Ok(em[zero_index + 1..].to_vec())
    }

    impl Rsa<Public> {
        pub fn new() -> Self {
            Self::from_key(RsaKey::None)
        }

        /// Checks that the modulus and the public exponent are valid, with the
        /// same rules as BoringSSL: a positive odd modulus of 512 to 16384 bits,
        /// and an odd exponent greater than 1 and of at most 33 bits.
        ///
        /// It does not enforce any application policy on the key size.
        pub fn check_key(&self) -> Result<bool, ErrorStack> {
            Ok(match &self.rsa_key {
                RsaKey::Public(x) => public_parameters_are_valid(x.n(), x.e()),
                _ => false,
            })
        }

        pub fn public_key_from_der(der: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let der = first_der_element(der).ok_or(ErrorStack::InvalidPublicKey)?;
            public_key_from_spki_der(der).map(|x| Self::from_key(RsaKey::Public(x)))
        }

        pub fn public_key_from_der_pkcs1(der: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            let der = first_der_element(der).ok_or(ErrorStack::InvalidPublicKey)?;
            public_key_from_pkcs1_der(der).map(|x| Self::from_key(RsaKey::Public(x)))
        }

        pub fn public_key_from_pem(pem: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            Self::public_key_from_der(&pem_der(pem, b"PUBLIC KEY")?)
        }

        pub fn public_key_from_pem_pkcs1(pem: &[u8]) -> Result<Rsa<Public>, ErrorStack> {
            Self::public_key_from_der_pkcs1(&pem_der(pem, b"RSA PUBLIC KEY")?)
        }

        /// Like BoringSSL, this accepts anything, and invalid keys only fail when they're checked or used.
        pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa<Public>, ErrorStack> {
            let rsa_key = match new_public_key(n.clone(), e.clone()) {
                Ok(rsa_key) => RsaKey::Public(rsa_key),
                Err(_) => RsaKey::Invalid(Box::new(InvalidKey {
                    n,
                    e,
                    private: None,
                    usable: None,
                })),
            };
            Ok(Self::from_key(rsa_key))
        }

        pub fn public_key_to_der(&self) -> Result<Vec<u8>, ErrorStack> {
            public_key_der(&self.n(), &self.e())
        }

        pub fn public_key_to_der_pkcs1(&self) -> Result<Vec<u8>, ErrorStack> {
            public_key_der_pkcs1(&self.n(), &self.e())
        }

        pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
            to_pem("PUBLIC KEY", &self.public_key_to_der()?)
        }

        pub fn public_key_to_pem_pkcs1(&self) -> Result<Vec<u8>, ErrorStack> {
            to_pem("RSA PUBLIC KEY", &self.public_key_to_der_pkcs1()?)
        }

        pub fn public_encrypt(
            &self,
            from: &[u8],
            to: &mut [u8],
            padding: Padding,
        ) -> Result<usize, ErrorStack> {
            let rsa_key = self
                .rsa_key
                .public_key()
                .ok_or(ErrorStack::InvalidPublicKey)?;
            let mut rng = rand::rng();
            let c = match padding.id {
                PaddingId::None => raw_public_op(rsa_key, from)?,
                PaddingId::Pkcs1 => rsa_key
                    .encrypt(&mut rng, rrsa::Pkcs1v15Encrypt, from)
                    .map_err(|_| ErrorStack::InvalidPublicKey)?,
                PaddingId::Pkcs1Pss => return Err(ErrorStack::KeyError),
                PaddingId::Pkcs1Oaep => rsa_key
                    .encrypt(&mut rng, rrsa::Oaep::<Sha1>::new(), from)
                    .map_err(|_| ErrorStack::InvalidPublicKey)?,
            };
            let len = c.len();
            to.fill(0);
            to[0..len].copy_from_slice(&c);
            Ok(len)
        }
    }

    impl Rsa<Private> {
        /// Like BoringSSL, the size is rounded down to a multiple of 128 bits, and has to end up between 512 and 16384 bits.
        pub fn generate(bits: u32) -> Result<Rsa<Private>, ErrorStack> {
            if bits > *MODULUS_BITS.end() as u32 {
                return Err(ErrorStack::UnsupportedModulus);
            }
            let bits = bits & !127;
            if bits < *MODULUS_BITS.start() as u32 {
                return Err(ErrorStack::UnsupportedModulus);
            }
            // The rsa crate would refuse anything below 1024 bits.
            let generate = || {
                rrsa::PrivateKey::new_unchecked(&mut rand::rng(), bits as _)
                    .map_err(|_| ErrorStack::InternalError)
            };
            #[cfg(not(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            )))]
            let rsa_key = generate()?;
            #[cfg(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            ))]
            let rsa_key = if let Some(rsa_key) = wasi_crypto::rsa_generate(bits)? {
                rsa_key
            } else {
                generate()?
            };
            Ok(Self::from_key(RsaKey::Private(rsa_key)))
        }

        /// Checks the consistency of a private key, like BoringSSL's
        /// `RSA_check_key()`: valid public parameters, `d < n`, `n = p * q`, and
        /// `d * e = 1` modulo `p - 1` and `q - 1`.
        ///
        /// It does not enforce any application policy on the key size.
        pub fn check_key(&self) -> Result<bool, ErrorStack> {
            Ok(match &self.rsa_key {
                RsaKey::Private(x) => {
                    public_parameters_are_valid(x.n(), x.e()) && x.validate().is_ok()
                }
                _ => false,
            })
        }

        pub fn public_key(&self) -> Result<Rsa<Public>, ErrorStack> {
            match &self.rsa_key {
                RsaKey::Private(x) => Ok(Rsa::from_key(RsaKey::Public(x.to_public_key()))),
                _ => Rsa::from_public_components(self.n(), self.e()),
            }
        }

        /// Like BoringSSL, this accepts anything, and invalid keys only fail when they're checked or used.
        #[allow(clippy::too_many_arguments)]
        pub fn from_private_components(
            n: BigNum,
            e: BigNum,
            d: BigNum,
            p: BigNum,
            q: BigNum,
            dmp1: BigNum,
            dmq1: BigNum,
            iqmp: BigNum,
        ) -> Result<Rsa<Private>, ErrorStack> {
            let private = PrivateParts {
                d,
                p,
                q,
                dmp1,
                dmq1,
                iqmp,
            };
            let rsa_key = match Self::checked_private_components(&n, &e, &private) {
                Ok(rsa_key) => RsaKey::Private(rsa_key),
                Err(_) => {
                    let usable = Self::usable_despite_check_key(&n, &e, &private);
                    RsaKey::Invalid(Box::new(InvalidKey {
                        n,
                        e,
                        private: Some(private),
                        usable,
                    }))
                }
            };
            Ok(Self::from_key(rsa_key))
        }

        /// BoringSSL can still use some keys that fail `check_key()`, because it only needs some of the components.
        ///
        /// It uses the CRT values when both primes have the same size in machine words, and `d` otherwise.
        /// If those are right, a valid key gives the same results.
        fn usable_despite_check_key(
            n: &BigNum,
            e: &BigNum,
            private: &PrivateParts,
        ) -> Option<rrsa::PrivateKey> {
            let PrivateParts {
                d,
                p,
                q,
                dmp1,
                dmq1,
                iqmp,
            } = private;
            let words = |x: &BigNum| (x.rsa_bn.bit_width() as usize).div_ceil(usize::BITS as usize);
            // Cheap checks first, so huge values never get to the math.
            // BoringSSL also needs d, dmp1, dmq1 and iqmp to fit in the size of n, p, q and p.
            let n_bits = n.rsa_bn.bit_width_vartime() as usize;
            if !MODULUS_BITS.contains(&n_bits)
                || p.rsa_bn >= n.rsa_bn
                || q.rsa_bn >= n.rsa_bn
                || words(d) > words(n)
                || words(dmp1) > words(p)
                || words(dmq1) > words(q)
                || words(iqmp) > words(p)
            {
                return None;
            }
            if words(p) == words(q) {
                let rsa_key = rrsa::PrivateKey::from_p_q(
                    p.rsa_bn.clone(),
                    q.rsa_bn.clone(),
                    e.rsa_bn.clone(),
                )
                .ok()?;
                (*rsa_key.n().as_ref() == n.rsa_bn && crt_values_match(&rsa_key, private))
                    .then_some(rsa_key)
            } else {
                rrsa::PrivateKey::from_components_with_wide_primes(
                    n.rsa_bn.clone(),
                    e.rsa_bn.clone(),
                    d.rsa_bn.clone(),
                    vec![p.rsa_bn.clone(), q.rsa_bn.clone()],
                )
                .ok()
            }
        }

        /// The rsa crate computes the CRT values itself, so the given ones have to match.
        fn checked_private_components(
            n: &BigNum,
            e: &BigNum,
            private: &PrivateParts,
        ) -> Result<rrsa::PrivateKey, ErrorStack> {
            let n_bits = n.rsa_bn.bit_width_vartime();
            if !MODULUS_BITS.contains(&(n_bits as usize)) {
                return Err(ErrorStack::InvalidPrivateKey);
            }
            // The rsa crate needs a slower constructor for primes of different sizes.
            // Choosing it leaks that the key is unbalanced, but so does BoringSSL.
            let half = n_bits.div_ceil(2);
            let balanced =
                private.p.rsa_bn.bit_width() <= half && private.q.rsa_bn.bit_width() <= half;
            let from_components = if balanced {
                rrsa::PrivateKey::from_components
            } else {
                rrsa::PrivateKey::from_components_with_wide_primes
            };
            let rsa_key = from_components(
                n.rsa_bn.clone(),
                e.rsa_bn.clone(),
                private.d.rsa_bn.clone(),
                vec![private.p.rsa_bn.clone(), private.q.rsa_bn.clone()],
            )
            .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            if !crt_values_match(&rsa_key, private) {
                return Err(ErrorStack::InvalidPrivateKey);
            }
            Ok(rsa_key)
        }

        fn from_pkcs8_der(der: &[u8], strict: bool) -> Result<Rsa<Private>, ErrorStack> {
            let key = pkcs8_rsa_private_key(der, strict).ok_or(ErrorStack::InvalidPrivateKey)?;
            Self::from_pkcs1_der(key)
        }

        fn from_pkcs1_der(der: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
            let key = rrsa::pkcs1::RsaPrivateKeyRef::try_from(der)
                .map_err(|_| ErrorStack::InvalidPrivateKey)?;
            if key.version() != rrsa::pkcs1::Version::TwoPrime {
                return Err(ErrorStack::InvalidPrivateKey);
            }
            let bn = |x: rrsa::pkcs1::UintRef<'_>| BigNum::from_slice(x.as_bytes());
            let private = PrivateParts {
                d: bn(key.private_exponent)?,
                p: bn(key.prime1)?,
                q: bn(key.prime2)?,
                dmp1: bn(key.exponent1)?,
                dmq1: bn(key.exponent2)?,
                iqmp: bn(key.coefficient)?,
            };
            let (n, e) = (bn(key.modulus)?, bn(key.public_exponent)?);
            let rsa_key = Self::checked_private_components(&n, &e, &private)?;
            Ok(Self::from_key(RsaKey::Private(rsa_key)))
        }

        /// Parses a PKCS#8 or PKCS#1 private key, checking every encoded value including
        /// the CRT parameters.
        ///
        /// Like BoringSSL, the first private key in the input is used, even if it's not RSA.
        pub fn private_key_from_pem(pem: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
            const PRIVATE_KEY_LABELS: [&[u8]; 5] = [
                b"PRIVATE KEY",
                b"ENCRYPTED PRIVATE KEY",
                b"RSA PRIVATE KEY",
                b"EC PRIVATE KEY",
                b"DSA PRIVATE KEY",
            ];
            let (label, der) = pem::read(pem, |label| PRIVATE_KEY_LABELS.contains(&label))
                .ok_or(ErrorStack::InvalidPrivateKey)?;
            let der = first_der_element(&der).ok_or(ErrorStack::InvalidPrivateKey)?;
            match label.as_slice() {
                b"PRIVATE KEY" => Self::from_pkcs8_der(der, true),
                // BoringSSL also tries PKCS#8 here.
                b"RSA PRIVATE KEY" => {
                    Self::from_pkcs1_der(der).or_else(|_| Self::from_pkcs8_der(der, false))
                }
                _ => Err(ErrorStack::InvalidPrivateKey),
            }
        }

        /// Parses a PKCS#1 private key, checking every value including the CRT parameters.
        ///
        /// Like BoringSSL, PKCS#8 isn't accepted, and anything after the key is ignored.
        pub fn private_key_from_der(der: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
            Self::from_pkcs1_der(first_der_element(der).ok_or(ErrorStack::InvalidPrivateKey)?)
        }

        /// Serializes the key as PKCS#1, like BoringSSL.
        pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
            to_pem("RSA PRIVATE KEY", &self.private_key_to_der()?)
        }

        /// Serializes the key as PKCS#1, like BoringSSL.
        pub fn private_key_to_der(&self) -> Result<Vec<u8>, ErrorStack> {
            match &self.rsa_key {
                RsaKey::Private(x) => Ok(x
                    .to_pkcs1_der()
                    .map_err(|_| ErrorStack::InvalidPrivateKey)?
                    .as_bytes()
                    .to_vec()),
                RsaKey::Invalid(x) => private_key_der(&x.n, &x.e, self.rsa_key.invalid_private()),
                _ => unreachable!(),
            }
        }

        pub fn d(&self) -> BigNum {
            match &self.rsa_key {
                RsaKey::Private(x) => bn(x.d()),
                _ => self.rsa_key.invalid_private().d.clone(),
            }
        }

        pub fn p(&self) -> BigNum {
            match &self.rsa_key {
                RsaKey::Private(x) => bn(x.primes()[0].as_ref()),
                _ => self.rsa_key.invalid_private().p.clone(),
            }
        }

        pub fn q(&self) -> BigNum {
            match &self.rsa_key {
                RsaKey::Private(x) => bn(x.primes()[1].as_ref()),
                _ => self.rsa_key.invalid_private().q.clone(),
            }
        }

        /// `d mod (p - 1)`
        pub fn dmp1(&self) -> Option<BigNum> {
            match &self.rsa_key {
                RsaKey::Private(x) => x.dp().map(bn),
                _ => Some(self.rsa_key.invalid_private().dmp1.clone()),
            }
        }

        /// `d mod (q - 1)`
        pub fn dmq1(&self) -> Option<BigNum> {
            match &self.rsa_key {
                RsaKey::Private(x) => x.dq().map(bn),
                _ => Some(self.rsa_key.invalid_private().dmq1.clone()),
            }
        }

        /// `q^-1 mod p`
        pub fn iqmp(&self) -> Option<BigNum> {
            match &self.rsa_key {
                RsaKey::Private(x) => x.qinv().map(|x| bn(&x.retrieve())),
                _ => Some(self.rsa_key.invalid_private().iqmp.clone()),
            }
        }

        pub fn private_decrypt(
            &self,
            from: &[u8],
            to: &mut [u8],
            padding: Padding,
        ) -> Result<usize, ErrorStack> {
            let rsa_key = self
                .rsa_key
                .private_key()
                .ok_or(ErrorStack::InvalidPrivateKey)?;
            let m = match padding.id {
                PaddingId::None => raw_private_op(rsa_key, from)?,
                PaddingId::Pkcs1 => pkcs1v15_decrypt(rsa_key, from)?,
                PaddingId::Pkcs1Pss => return Err(ErrorStack::KeyError),
                PaddingId::Pkcs1Oaep => rsa_key
                    .decrypt_blinded(&mut rand::rng(), rrsa::Oaep::<Sha1>::new(), from)
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

    enum AesKeyInner {
        Aes128(Box<Aes128KeyWrapAligned>),
        Aes256(Box<Aes256KeyWrapAligned>),
    }

    impl std::fmt::Debug for AesKeyInner {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                AesKeyInner::Aes128(_) => write!(f, "Aes128"),
                AesKeyInner::Aes256(_) => write!(f, "Aes256"),
            }
        }
    }

    pub struct AesKey {
        inner: AesKeyInner,
    }

    impl std::fmt::Debug for AesKey {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "AesKey")
        }
    }

    pub type KeyError = ErrorStack;

    impl AesKey {
        pub fn new_encrypt(key: &[u8]) -> Result<AesKey, KeyError> {
            let inner = match key.len() {
                16 => {
                    let key_arr: [u8; 16] = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                    AesKeyInner::Aes128(Box::new(Aes128KeyWrapAligned::new(&key_arr)))
                }
                32 => {
                    let key_arr: [u8; 32] = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                    AesKeyInner::Aes256(Box::new(Aes256KeyWrapAligned::new(&key_arr)))
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

    #[derive(Clone, PartialEq, Eq)]
    pub struct BigNum {
        pub rsa_bn: rrsa::BoxedUint,
    }

    impl std::fmt::Debug for BigNum {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "BigNum")
        }
    }

    pub type BigNumRef<'a> = BigNum;

    impl BigNum {
        pub fn from_slice(slice: &[u8]) -> Result<Self, ErrorStack> {
            // crypto-bigint can't handle an integer with no limbs at all.
            let rsa_bn = if slice.is_empty() {
                rrsa::BoxedUint::zero()
            } else {
                rrsa::BoxedUint::from_be_slice_vartime(slice)
            };
            Ok(BigNum { rsa_bn })
        }

        pub fn to_vec(&self) -> Vec<u8> {
            self.rsa_bn.to_be_bytes_trimmed_vartime().into_vec()
        }

        pub fn to_owned(&self) -> Result<BigNum, ErrorStack> {
            Ok(self.clone())
        }

        /// Returns the number of significant bits in `self`.
        pub fn num_bits(&self) -> i32 {
            self.rsa_bn.bit_width() as i32
        }

        /// Returns the size of `self` in bytes.
        pub fn num_bytes(&self) -> i32 {
            (self.num_bits() + 7) / 8
        }
    }
}

#[allow(unused_imports)]
use nid::*;
pub mod nid {
    use std::ffi::c_int;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct Nid(c_int);

    impl Nid {
        pub fn from_raw(raw: c_int) -> Nid {
            Nid(raw)
        }

        pub fn as_raw(&self) -> c_int {
            self.0
        }

        pub const UNDEF: Nid = Nid(0);
        pub const SHA256: Nid = Nid(672);
        pub const SHA384: Nid = Nid(673);
        pub const SHA512: Nid = Nid(674);
        pub const AES_128_GCM: Nid = Nid(895);
        pub const AES_256_GCM: Nid = Nid(901);
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

        pub fn type_(&self) -> Nid {
            match self {
                MessageDigest::Sha256 => Nid::SHA256,
                MessageDigest::Sha384 => Nid::SHA384,
                MessageDigest::Sha512 => Nid::SHA512,
            }
        }

        /// The size of the digest in bytes.
        pub fn size(&self) -> usize {
            match self {
                MessageDigest::Sha256 => 32,
                MessageDigest::Sha384 => 48,
                MessageDigest::Sha512 => 64,
            }
        }

        pub fn from_nid(type_: Nid) -> Option<MessageDigest> {
            match type_ {
                Nid::SHA256 => Some(MessageDigest::Sha256),
                Nid::SHA384 => Some(MessageDigest::Sha384),
                Nid::SHA512 => Some(MessageDigest::Sha512),
                _ => None,
            }
        }
    }
}

#[allow(unused_imports)]
use hmac::*;
pub mod hmac {
    use super::*;

    enum HmacInner {
        Sha256(HmacSha256),
        Sha384(HmacSha384),
        Sha512(HmacSha512),
        #[cfg(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        ))]
        WasiSha256(wasi_crypto::WasiAuth),
        #[cfg(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        ))]
        WasiSha512(wasi_crypto::WasiAuth),
    }

    pub struct Hmac {
        inner: HmacInner,
    }

    impl Hmac {
        pub fn init(key: &[u8], md: &MessageDigest) -> Result<Hmac, ErrorStack> {
            #[cfg(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            ))]
            if let Some(alg) = wasi_crypto::hmac_alg(md) {
                let auth = wasi_crypto::auth_new(alg, key)?;
                let inner = match md {
                    MessageDigest::Sha256 => HmacInner::WasiSha256(auth),
                    MessageDigest::Sha384 => unreachable!(),
                    MessageDigest::Sha512 => HmacInner::WasiSha512(auth),
                };
                return Ok(Hmac { inner });
            }
            let inner = match md {
                MessageDigest::Sha256 => HmacInner::Sha256(HmacSha256::new(key)),
                MessageDigest::Sha384 => HmacInner::Sha384(HmacSha384::new(key)),
                MessageDigest::Sha512 => HmacInner::Sha512(HmacSha512::new(key)),
            };
            Ok(Hmac { inner })
        }

        pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
            match &mut self.inner {
                HmacInner::Sha256(h) => h.update(data),
                HmacInner::Sha384(h) => h.update(data),
                HmacInner::Sha512(h) => h.update(data),
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                HmacInner::WasiSha256(h) => wasi_crypto::auth_absorb(h, data)?,
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                HmacInner::WasiSha512(h) => wasi_crypto::auth_absorb(h, data)?,
            }
            Ok(())
        }

        pub fn finalize(self) -> Result<Vec<u8>, ErrorStack> {
            let result = match self.inner {
                HmacInner::Sha256(h) => h.finalize().to_vec(),
                HmacInner::Sha384(h) => h.finalize().to_vec(),
                HmacInner::Sha512(h) => h.finalize().to_vec(),
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                HmacInner::WasiSha256(mut h) => wasi_crypto::auth_tag(&mut h)?,
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                HmacInner::WasiSha512(mut h) => wasi_crypto::auth_tag(&mut h)?,
            };
            Ok(result)
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
    #[derive(Clone, Default, PartialEq, Eq)]
    pub enum PKey<T> {
        #[default]
        None,
        Rsa(Rsa<T>),
    }

    impl<T> std::fmt::Debug for PKey<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                PKey::None => f.debug_struct("PKey").finish(),
                PKey::Rsa(_) => f.debug_struct("PKey").field("algorithm", &"RSA").finish(),
            }
        }
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

    #[derive(Clone)]
    pub enum AnyHash {
        Sha256(Sha256),
        Sha384(Sha384),
        Sha512(Sha512),
    }

    impl AnyHash {
        fn new(md: &MessageDigest) -> Self {
            match md {
                MessageDigest::Sha256 => AnyHash::Sha256(Sha256::new()),
                MessageDigest::Sha384 => AnyHash::Sha384(Sha384::new()),
                MessageDigest::Sha512 => AnyHash::Sha512(Sha512::new()),
            }
        }

        fn update(&mut self, buf: &[u8]) {
            match self {
                AnyHash::Sha256(x) => x.update(buf),
                AnyHash::Sha384(x) => x.update(buf),
                AnyHash::Sha512(x) => x.update(buf),
            }
        }

        fn finalize(&self) -> Vec<u8> {
            match self {
                AnyHash::Sha256(x) => x.finalize().to_vec(),
                AnyHash::Sha384(x) => x.finalize().to_vec(),
                AnyHash::Sha512(x) => x.finalize().to_vec(),
            }
        }
    }

    fn digest(md: &MessageDigest, parts: &[&[u8]]) -> Vec<u8> {
        let mut h = AnyHash::new(md);
        for part in parts {
            h.update(part);
        }
        h.finalize()
    }

    fn mgf1(md: &MessageDigest, seed: &[u8], len: usize) -> Vec<u8> {
        (0u32..)
            .flat_map(|counter| digest(md, &[seed, &counter.to_be_bytes()]))
            .take(len)
            .collect()
    }

    // PSS is ported from BoringSSL, because the rsa crate can't use a different hash for MGF1, and handles salt lengths differently.

    /// PSS encoding, ported from BoringSSL's `RSA_padding_add_PKCS1_PSS_mgf1()`.
    /// `MAXIMUM_LENGTH` means the longest salt that fits.
    fn pss_encode(
        m_hash: &[u8],
        md: &MessageDigest,
        mgf1_md: &MessageDigest,
        salt_len: RsaPssSaltlen,
        mod_bits: usize,
        k: usize,
    ) -> Result<Vec<u8>, ErrorStack> {
        let h_len = md.size();
        let ms_bits = (mod_bits - 1) & 7;
        let mut out = vec![0u8; k];
        // The encoded message is one byte shorter when the modulus size is a multiple of 8 plus 1.
        let em = if ms_bits == 0 {
            &mut out[1..]
        } else {
            &mut out[..]
        };
        let em_len = em.len();
        if em_len < h_len + 2 {
            return Err(ErrorStack::InternalError);
        }
        let s_len = match salt_len.len {
            -1 => h_len,
            -2 => em_len - h_len - 2,
            x => usize::try_from(x).map_err(|_| ErrorStack::InternalError)?,
        };
        if em_len - h_len - 2 < s_len {
            return Err(ErrorStack::InternalError);
        }
        let mut salt = vec![0u8; s_len];
        rand::fill(&mut salt);
        let h = digest(md, &[&[0u8; 8], m_hash, &salt]);
        let masked_db_len = em_len - h_len - 1;
        em[..masked_db_len].copy_from_slice(&mgf1(mgf1_md, &h, masked_db_len));
        let separator = em_len - s_len - h_len - 2;
        em[separator] ^= 1;
        for (x, s) in em[separator + 1..masked_db_len].iter_mut().zip(&salt) {
            *x ^= s;
        }
        if ms_bits != 0 {
            em[0] &= 0xff >> (8 - ms_bits);
        }
        em[masked_db_len..em_len - 1].copy_from_slice(&h);
        em[em_len - 1] = 0xbc;
        Ok(out)
    }

    /// PSS verification, ported from BoringSSL's `RSA_verify_PKCS1_PSS_mgf1()`.
    /// `MAXIMUM_LENGTH` accepts any salt length.
    fn pss_verify(
        m_hash: &[u8],
        md: &MessageDigest,
        mgf1_md: &MessageDigest,
        salt_len: RsaPssSaltlen,
        mod_bits: usize,
        em: &[u8],
    ) -> bool {
        let h_len = md.size();
        let s_len = match salt_len.len {
            -1 => Some(h_len),
            -2 => None,
            x => match usize::try_from(x) {
                Ok(x) => Some(x),
                Err(_) => return false,
            },
        };
        let ms_bits = (mod_bits - 1) & 7;
        if em[0] & (0xffu8 << ms_bits) != 0 {
            return false;
        }
        let em = if ms_bits == 0 { &em[1..] } else { em };
        let em_len = em.len();
        if em_len < h_len + 2 || s_len.is_some_and(|s_len| em_len < h_len + s_len + 2) {
            return false;
        }
        if em[em_len - 1] != 0xbc {
            return false;
        }
        let masked_db_len = em_len - h_len - 1;
        let h = &em[masked_db_len..em_len - 1];
        let mut db = mgf1(mgf1_md, h, masked_db_len);
        for (x, m) in db.iter_mut().zip(em) {
            *x ^= m;
        }
        if ms_bits != 0 {
            db[0] &= 0xff >> (8 - ms_bits);
        }
        // Zeros, a one, then the salt.
        let mut salt_start = 0;
        while db[salt_start] == 0 && salt_start < masked_db_len - 1 {
            salt_start += 1;
        }
        if db[salt_start] != 1 {
            return false;
        }
        salt_start += 1;
        if s_len.is_some_and(|s_len| masked_db_len - salt_start != s_len) {
            return false;
        }
        digest(md, &[&[0u8; 8], m_hash, &db[salt_start..]]) == h
    }

    fn pkcs1v15_scheme(md: &MessageDigest) -> rrsa::Pkcs1v15Sign {
        match md {
            MessageDigest::Sha256 => rrsa::Pkcs1v15Sign::new::<Sha256>(),
            MessageDigest::Sha384 => rrsa::Pkcs1v15Sign::new::<Sha384>(),
            MessageDigest::Sha512 => rrsa::Pkcs1v15Sign::new::<Sha512>(),
        }
    }

    // Signers and verifiers refuse the same options as BoringSSL: only PKCS#1 v1.5 and PSS padding, and salt lengths and MGF1 hashes only with PSS.

    fn check_signature_padding(padding: Padding) -> Result<(), ErrorStack> {
        if padding == Padding::PKCS1 || padding == Padding::PKCS1_PSS {
            Ok(())
        } else {
            Err(ErrorStack::KeyError)
        }
    }

    fn check_pss_padding(padding: Padding) -> Result<(), ErrorStack> {
        if padding == Padding::PKCS1_PSS {
            Ok(())
        } else {
            Err(ErrorStack::KeyError)
        }
    }

    /// The state and options signers and verifiers have in common.
    #[derive(Clone)]
    pub struct SignatureContext<'t, T, Op> {
        pub message_digest: MessageDigest,
        pub pkey_ref: &'t PKey<T>,
        pub padding: Padding,
        pub salt_len: RsaPssSaltlen,
        pub mgf1_md: Option<MessageDigest>,
        pub any_hash: AnyHash,
        #[cfg(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        ))]
        pub wasi_buf: Vec<u8>,
        _op: std::marker::PhantomData<Op>,
    }

    #[derive(Clone)]
    pub enum Sign {}

    #[derive(Clone)]
    pub enum Verify {}

    pub type Signer<'t, T> = SignatureContext<'t, T, Sign>;
    pub type Verifier<'t, T> = SignatureContext<'t, T, Verify>;

    impl<'t, T, Op> SignatureContext<'t, T, Op> {
        fn with_digest(type_: MessageDigest, pkey: &'t PKey<T>) -> Self {
            SignatureContext {
                any_hash: AnyHash::new(&type_),
                message_digest: type_,
                pkey_ref: pkey,
                padding: Padding::PKCS1,
                salt_len: RsaPssSaltlen::default(),
                mgf1_md: None,
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                wasi_buf: Vec::new(),
                _op: std::marker::PhantomData,
            }
        }

        pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
            check_signature_padding(padding)?;
            self.padding = padding;
            Ok(())
        }

        pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
            Ok(self.padding)
        }

        pub fn set_rsa_pss_saltlen(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
            check_pss_padding(self.padding)?;
            if len.len < -2 {
                return Err(ErrorStack::KeyError);
            }
            self.salt_len = len;
            Ok(())
        }

        pub fn rsa_pss_saltlen(&self) -> Result<RsaPssSaltlen, ErrorStack> {
            check_pss_padding(self.padding)?;
            Ok(self.salt_len)
        }

        pub fn set_rsa_mgf1_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
            check_pss_padding(self.padding)?;
            self.mgf1_md = Some(md);
            Ok(())
        }

        pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
            #[cfg(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            ))]
            self.wasi_buf.extend_from_slice(buf);
            self.any_hash.update(buf);
            Ok(())
        }

        fn rsa_key(&self) -> &RsaKey {
            let PKey::Rsa(rsa) = self.pkey_ref else {
                unreachable!();
            };
            &rsa.rsa_key
        }

        fn mgf1_md(&self) -> &MessageDigest {
            self.mgf1_md.as_ref().unwrap_or(&self.message_digest)
        }
    }

    impl<'t, T> Signer<'t, T> {
        pub fn new(type_: MessageDigest, pkey: &'t PKey<T>) -> Result<Signer<'t, T>, ErrorStack>
        where
            T: HasPrivate,
        {
            Ok(Self::with_digest(type_, pkey))
        }

        #[allow(clippy::len_without_is_empty)]
        pub fn len(&self) -> Result<usize, ErrorStack> {
            Ok(self.rsa_key().size())
        }

        pub fn sign(&self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
            let sig = self.sign_to_vec()?;
            if buf.len() < sig.len() {
                return Err(ErrorStack::Overflow);
            }
            buf[..sig.len()].copy_from_slice(&sig);
            Ok(sig.len())
        }

        pub fn sign_to_vec(&self) -> Result<Vec<u8>, ErrorStack> {
            check_signature_padding(self.padding)?;
            let rsa_key = self
                .rsa_key()
                .private_key()
                .ok_or(ErrorStack::InvalidPrivateKey)?;
            #[cfg(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            ))]
            if let Some(sig) = wasi_crypto::rsa_sign(
                rsa_key,
                self.padding,
                &self.message_digest,
                self.mgf1_md(),
                self.salt_len,
                &self.wasi_buf,
            )? {
                return Ok(sig);
            }
            let hashed = self.any_hash.finalize();
            if self.padding == Padding::PKCS1_PSS {
                let em = pss_encode(
                    &hashed,
                    &self.message_digest,
                    self.mgf1_md(),
                    self.salt_len,
                    rsa_key.n().bit_width_vartime() as usize,
                    rsa_key.size(),
                )?;
                return raw_private_op(rsa_key, &em);
            }
            rsa_key
                .sign_with_rng(
                    &mut rand::rng(),
                    pkcs1v15_scheme(&self.message_digest),
                    &hashed,
                )
                .map_err(|_| ErrorStack::InternalError)
        }

        pub fn sign_oneshot(
            &mut self,
            sig_buf: &mut [u8],
            data_buf: &[u8],
        ) -> Result<usize, ErrorStack> {
            self.update(data_buf)?;
            self.sign(sig_buf)
        }

        pub fn sign_oneshot_to_vec(&mut self, data_buf: &[u8]) -> Result<Vec<u8>, ErrorStack> {
            self.update(data_buf)?;
            self.sign_to_vec()
        }
    }

    impl<'t, T> Verifier<'t, T> {
        pub fn new(type_: MessageDigest, pkey: &'t PKey<T>) -> Result<Verifier<'t, T>, ErrorStack>
        where
            T: HasPublic,
        {
            Ok(Self::with_digest(type_, pkey))
        }

        pub fn verify(&self, signature: &[u8]) -> Result<bool, ErrorStack> {
            check_signature_padding(self.padding)?;
            let Some(rsa_key) = self.rsa_key().public_key() else {
                return Ok(false);
            };
            #[cfg(all(
                feature = "wasi-crypto",
                target_arch = "wasm32",
                target_os = "wasi",
                target_env = "p1"
            ))]
            if let Some(ok) = wasi_crypto::rsa_verify(
                rsa_key,
                self.padding,
                &self.message_digest,
                self.mgf1_md(),
                self.salt_len,
                &self.wasi_buf,
                signature,
            )? {
                return Ok(ok);
            }
            let hashed = self.any_hash.finalize();
            if self.padding == Padding::PKCS1_PSS {
                let Ok(em) = raw_public_op(rsa_key, signature) else {
                    return Ok(false);
                };
                return Ok(pss_verify(
                    &hashed,
                    &self.message_digest,
                    self.mgf1_md(),
                    self.salt_len,
                    rsa_key.n().bit_width_vartime() as usize,
                    &em,
                ));
            }
            Ok(rsa_key
                .verify(pkcs1v15_scheme(&self.message_digest), &hashed, signature)
                .is_ok())
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
    #[cfg(not(all(
        feature = "wasi-crypto",
        target_arch = "wasm32",
        target_os = "wasi",
        target_env = "p1"
    )))]
    use aes_gcm::aead::{AeadInOut, KeyInit};
    #[cfg(not(all(
        feature = "wasi-crypto",
        target_arch = "wasm32",
        target_os = "wasi",
        target_env = "p1"
    )))]
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

        pub fn nid(&self) -> Nid {
            match self.cipher_type {
                CipherType::Aes128Gcm => Nid::AES_128_GCM,
                CipherType::Aes256Gcm => Nid::AES_256_GCM,
            }
        }
    }

    enum AesGcmCipher {
        #[cfg(not(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        )))]
        Aes128(Box<Aes128Gcm>),
        #[cfg(not(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        )))]
        Aes256(Box<Aes256Gcm>),
        #[cfg(all(
            feature = "wasi-crypto",
            target_arch = "wasm32",
            target_os = "wasi",
            target_env = "p1"
        ))]
        Wasi(wasi_crypto::WasiAeadKey),
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
                    #[cfg(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    ))]
                    {
                        AesGcmCipher::Wasi(wasi_crypto::aead_key("AES-128-GCM", key)?)
                    }
                    #[cfg(not(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    )))]
                    {
                        let key_arr = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                        AesGcmCipher::Aes128(Box::new(Aes128Gcm::new(key_arr)))
                    }
                }
                CipherType::Aes256Gcm => {
                    if key.len() != 32 {
                        return Err(ErrorStack::KeyError);
                    }
                    #[cfg(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    ))]
                    {
                        AesGcmCipher::Wasi(wasi_crypto::aead_key("AES-256-GCM", key)?)
                    }
                    #[cfg(not(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    )))]
                    {
                        let key_arr = key.try_into().map_err(|_| ErrorStack::KeyError)?;
                        AesGcmCipher::Aes256(Box::new(Aes256Gcm::new(key_arr)))
                    }
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
            match self.mode {
                Mode::Encrypt => {
                    self.input_buf = input.to_vec();
                    #[cfg(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    ))]
                    let tag = {
                        let AesGcmCipher::Wasi(c) = &self.cipher;
                        wasi_crypto::aead_encrypt_detached(
                            c,
                            &self.nonce,
                            &self.aad,
                            &mut self.input_buf,
                            input,
                        )?
                    };
                    #[cfg(not(all(
                        feature = "wasi-crypto",
                        target_arch = "wasm32",
                        target_os = "wasi",
                        target_env = "p1"
                    )))]
                    let tag = {
                        let nonce = (&self.nonce).into();
                        let tag = match &self.cipher {
                            AesGcmCipher::Aes128(c) => c
                                .encrypt_inout_detached(
                                    nonce,
                                    &self.aad,
                                    self.input_buf.as_mut_slice().into(),
                                )
                                .map_err(|_| ErrorStack::KeyError)?,
                            AesGcmCipher::Aes256(c) => c
                                .encrypt_inout_detached(
                                    nonce,
                                    &self.aad,
                                    self.input_buf.as_mut_slice().into(),
                                )
                                .map_err(|_| ErrorStack::KeyError)?,
                        };
                        let mut tag_arr = [0u8; 16];
                        tag_arr.copy_from_slice(&tag);
                        tag_arr
                    };
                    output[..self.input_buf.len()].copy_from_slice(&self.input_buf);
                    self.output_tag = Some(tag);
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
                let tag_arr = self.tag.ok_or(ErrorStack::KeyError)?;
                #[cfg(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                ))]
                {
                    let AesGcmCipher::Wasi(c) = &self.cipher;
                    let ciphertext = self.input_buf.clone();
                    wasi_crypto::aead_decrypt_detached(
                        c,
                        &self.nonce,
                        &self.aad,
                        &mut self.input_buf,
                        &ciphertext,
                        &tag_arr,
                    )?;
                }
                #[cfg(not(all(
                    feature = "wasi-crypto",
                    target_arch = "wasm32",
                    target_os = "wasi",
                    target_env = "p1"
                )))]
                {
                    let nonce = (&self.nonce).into();
                    let tag = (&tag_arr).into();
                    match &self.cipher {
                        AesGcmCipher::Aes128(c) => c
                            .decrypt_inout_detached(
                                nonce,
                                &self.aad,
                                self.input_buf.as_mut_slice().into(),
                                tag,
                            )
                            .map_err(|_| ErrorStack::KeyError)?,
                        AesGcmCipher::Aes256(c) => c
                            .decrypt_inout_detached(
                                nonce,
                                &self.aad,
                                self.input_buf.as_mut_slice().into(),
                                tag,
                            )
                            .map_err(|_| ErrorStack::KeyError)?,
                    };
                }
                if let Some(ptr) = self.output_ptr {
                    let copy_len = self.output_len.min(self.input_buf.len());
                    unsafe {
                        std::ptr::copy_nonoverlapping(self.input_buf.as_ptr(), ptr, copy_len);
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

#[allow(unused_imports)]
use mldsa::*;
pub mod mldsa {
    use super::*;

    use ml_dsa::EncodedVerifyingKey;

    pub const PRIVATE_KEY_SEED_BYTES: usize = 32;
    pub type MlDsaPrivateKeySeed = [u8; PRIVATE_KEY_SEED_BYTES];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Algorithm {
        MlDsa44,
        MlDsa65,
        MlDsa87,
    }

    impl Algorithm {
        #[must_use]
        pub const fn public_key_bytes(&self) -> usize {
            match self {
                Algorithm::MlDsa44 => 1312,
                Algorithm::MlDsa65 => 1952,
                Algorithm::MlDsa87 => 2592,
            }
        }

        #[must_use]
        pub const fn signature_bytes(&self) -> usize {
            match self {
                Algorithm::MlDsa44 => 2420,
                Algorithm::MlDsa65 => 3309,
                Algorithm::MlDsa87 => 4627,
            }
        }
    }

    #[derive(Clone)]
    enum VerifyingKeyInner {
        MlDsa44(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>),
        MlDsa65(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>),
        MlDsa87(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>),
    }

    #[derive(Clone)]
    pub struct MlDsaPublicKey {
        algorithm: Algorithm,
        inner: VerifyingKeyInner,
    }

    impl MlDsaPublicKey {
        pub fn from_slice(
            algorithm: Algorithm,
            serialized_public_key: &[u8],
        ) -> Result<Self, ErrorStack> {
            fn decode<P: ml_dsa::MlDsaParams>(
                bytes: &[u8],
            ) -> Result<Box<ml_dsa::VerifyingKey<P>>, ErrorStack> {
                // The encoded key type has a fixed size, hence no explicit length check.
                let enc = EncodedVerifyingKey::<P>::try_from(bytes)
                    .map_err(|_| ErrorStack::InvalidPublicKey)?;
                Ok(Box::new(ml_dsa::VerifyingKey::decode(&enc)))
            }

            let inner = match algorithm {
                Algorithm::MlDsa44 => VerifyingKeyInner::MlDsa44(decode(serialized_public_key)?),
                Algorithm::MlDsa65 => VerifyingKeyInner::MlDsa65(decode(serialized_public_key)?),
                Algorithm::MlDsa87 => VerifyingKeyInner::MlDsa87(decode(serialized_public_key)?),
            };
            Ok(MlDsaPublicKey { algorithm, inner })
        }

        pub fn algorithm(&self) -> Algorithm {
            self.algorithm
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, ErrorStack> {
            Ok(match &self.inner {
                VerifyingKeyInner::MlDsa44(vk) => vk.encode().to_vec(),
                VerifyingKeyInner::MlDsa65(vk) => vk.encode().to_vec(),
                VerifyingKeyInner::MlDsa87(vk) => vk.encode().to_vec(),
            })
        }

        pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), ErrorStack> {
            let ok = match &self.inner {
                VerifyingKeyInner::MlDsa44(vk) => {
                    let sig = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(signature)
                        .map_err(|_| ErrorStack::KeyError)?;
                    vk.verify_with_context(msg, &[], &sig)
                }
                VerifyingKeyInner::MlDsa65(vk) => {
                    let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
                        .map_err(|_| ErrorStack::KeyError)?;
                    vk.verify_with_context(msg, &[], &sig)
                }
                VerifyingKeyInner::MlDsa87(vk) => {
                    let sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(signature)
                        .map_err(|_| ErrorStack::KeyError)?;
                    vk.verify_with_context(msg, &[], &sig)
                }
            };
            if ok {
                Ok(())
            } else {
                Err(ErrorStack::KeyError)
            }
        }
    }

    impl std::fmt::Debug for MlDsaPublicKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MlDsaPublicKey")
                .field("algorithm", &self.algorithm)
                .finish()
        }
    }

    #[derive(Clone)]
    enum SigningKeyInner {
        MlDsa44(Box<ml_dsa::SigningKey<ml_dsa::MlDsa44>>),
        MlDsa65(Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
        MlDsa87(Box<ml_dsa::SigningKey<ml_dsa::MlDsa87>>),
    }

    #[derive(Clone)]
    pub struct MlDsaPrivateKey {
        algorithm: Algorithm,
        seed: MlDsaPrivateKeySeed,
        inner: SigningKeyInner,
    }

    impl MlDsaPrivateKey {
        pub fn generate(
            algorithm: Algorithm,
        ) -> Result<(MlDsaPublicKey, MlDsaPrivateKey), ErrorStack> {
            let mut seed = [0u8; 32];
            rand::fill(&mut seed);
            let privkey = Self::from_seed(algorithm, &seed);
            seed.fill(0);
            let privkey = privkey?;
            let pubkey = privkey.public_key()?;
            Ok((pubkey, privkey))
        }

        pub fn from_seed(
            algorithm: Algorithm,
            seed: &MlDsaPrivateKeySeed,
        ) -> Result<Self, ErrorStack> {
            let b32 = ml_dsa::B32::from(*seed);
            let (inner, actual_seed) = match algorithm {
                Algorithm::MlDsa44 => {
                    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&b32);
                    let s: [u8; 32] = sk.to_seed().into();
                    (SigningKeyInner::MlDsa44(Box::new(sk)), s)
                }
                Algorithm::MlDsa65 => {
                    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&b32);
                    let s: [u8; 32] = sk.to_seed().into();
                    (SigningKeyInner::MlDsa65(Box::new(sk)), s)
                }
                Algorithm::MlDsa87 => {
                    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&b32);
                    let s: [u8; 32] = sk.to_seed().into();
                    (SigningKeyInner::MlDsa87(Box::new(sk)), s)
                }
            };
            Ok(MlDsaPrivateKey {
                algorithm,
                seed: actual_seed,
                inner,
            })
        }

        pub fn public_key(&self) -> Result<MlDsaPublicKey, ErrorStack> {
            let inner = match &self.inner {
                SigningKeyInner::MlDsa44(sk) => VerifyingKeyInner::MlDsa44(Box::new(
                    ml_dsa::signature::Keypair::verifying_key(sk.as_ref()),
                )),
                SigningKeyInner::MlDsa65(sk) => VerifyingKeyInner::MlDsa65(Box::new(
                    ml_dsa::signature::Keypair::verifying_key(sk.as_ref()),
                )),
                SigningKeyInner::MlDsa87(sk) => VerifyingKeyInner::MlDsa87(Box::new(
                    ml_dsa::signature::Keypair::verifying_key(sk.as_ref()),
                )),
            };
            Ok(MlDsaPublicKey {
                algorithm: self.algorithm,
                inner,
            })
        }

        pub fn algorithm(&self) -> Algorithm {
            self.algorithm
        }

        pub fn seed_bytes(&self) -> &MlDsaPrivateKeySeed {
            &self.seed
        }

        pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
            // BoringSSL uses the hedged variant, so we do too.
            let mut rng = ml_dsa::common::getrandom::SysRng;
            let sig_bytes = match &self.inner {
                SigningKeyInner::MlDsa44(sk) => sk
                    .expanded_key()
                    .sign_randomized(msg, &[], &mut rng)
                    .map_err(|_| ErrorStack::InternalError)?
                    .encode()
                    .to_vec(),
                SigningKeyInner::MlDsa65(sk) => sk
                    .expanded_key()
                    .sign_randomized(msg, &[], &mut rng)
                    .map_err(|_| ErrorStack::InternalError)?
                    .encode()
                    .to_vec(),
                SigningKeyInner::MlDsa87(sk) => sk
                    .expanded_key()
                    .sign_randomized(msg, &[], &mut rng)
                    .map_err(|_| ErrorStack::InternalError)?
                    .encode()
                    .to_vec(),
            };
            Ok(sig_bytes)
        }
    }

    impl std::fmt::Debug for MlDsaPrivateKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MlDsaPrivateKey")
                .field("algorithm", &self.algorithm)
                .field("seed", &"[redacted]")
                .finish()
        }
    }

    impl Drop for MlDsaPrivateKey {
        fn drop(&mut self) {
            self.seed.fill(0);
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
    use aes::{unwrap_key, wrap_key, AesKey};

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
    use aes::{unwrap_key, wrap_key, AesKey};

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

#[test]
fn test_hmac_sha256() {
    let mut h = hmac::Hmac::init(b"secret key", &MessageDigest::sha256()).unwrap();
    h.update(b"hello ").unwrap();
    h.update(b"world").unwrap();
    let mac = h.finalize().unwrap();
    assert_eq!(mac.len(), 32);

    let mut h2 = hmac::Hmac::init(b"secret key", &MessageDigest::sha256()).unwrap();
    h2.update(b"hello world").unwrap();
    let mac2 = h2.finalize().unwrap();
    assert_eq!(mac, mac2);
}

#[test]
fn test_hmac_sha384() {
    let mut h = hmac::Hmac::init(b"secret key", &MessageDigest::sha384()).unwrap();
    h.update(b"hello world").unwrap();
    let mac = h.finalize().unwrap();
    assert_eq!(mac.len(), 48);
}

#[test]
fn test_hmac_sha512() {
    let mut h = hmac::Hmac::init(b"secret key", &MessageDigest::sha512()).unwrap();
    h.update(b"hello ").unwrap();
    h.update(b"world").unwrap();
    let mac = h.finalize().unwrap();
    assert_eq!(mac.len(), 64);

    let mut h2 = hmac::Hmac::init(b"secret key", &MessageDigest::sha512()).unwrap();
    h2.update(b"hello world").unwrap();
    let mac2 = h2.finalize().unwrap();
    assert_eq!(mac, mac2);
}

#[test]
fn test_nid_roundtrip() {
    assert_eq!(
        MessageDigest::from_nid(Nid::SHA256),
        Some(MessageDigest::Sha256)
    );
    assert_eq!(
        MessageDigest::from_nid(Nid::SHA384),
        Some(MessageDigest::Sha384)
    );
    assert_eq!(
        MessageDigest::from_nid(Nid::SHA512),
        Some(MessageDigest::Sha512)
    );
    assert_eq!(MessageDigest::from_nid(Nid::UNDEF), None);
    assert_eq!(MessageDigest::sha256().type_(), Nid::SHA256);
}

#[test]
fn test_cipher_nid() {
    assert_eq!(symm::Cipher::aes_128_gcm().nid(), Nid::AES_128_GCM);
    assert_eq!(symm::Cipher::aes_256_gcm().nid(), Nid::AES_256_GCM);
}

#[test]
fn test_aes_128_gcm_known_vector() {
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let plaintext = [0u8; 16];
    let expected_ciphertext = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    let expected_tag = [
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd,
        0xdf,
    ];

    let mut enc = symm::Crypter::new(
        symm::Cipher::aes_128_gcm(),
        symm::Mode::Encrypt,
        &key,
        Some(&iv),
    )
    .unwrap();
    let mut ciphertext = [0u8; 16];
    assert_eq!(enc.update(&plaintext, &mut ciphertext).unwrap(), 16);
    assert_eq!(enc.finalize(&mut []).unwrap(), 0);
    let mut tag = [0u8; 16];
    enc.get_tag(&mut tag).unwrap();
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(tag, expected_tag);

    let mut dec = symm::Crypter::new(
        symm::Cipher::aes_128_gcm(),
        symm::Mode::Decrypt,
        &key,
        Some(&iv),
    )
    .unwrap();
    let mut recovered = [0u8; 16];
    assert_eq!(dec.update(&ciphertext, &mut recovered).unwrap(), 16);
    dec.set_tag(&tag).unwrap();
    assert_eq!(dec.finalize(&mut []).unwrap(), 0);
    assert_eq!(recovered, plaintext);
}

#[test]
fn test_aes_256_gcm_known_vector() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let plaintext = [0u8; 16];
    let expected_ciphertext = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d,
        0x18,
    ];
    let expected_tag = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9,
        0x19,
    ];

    let mut enc = symm::Crypter::new(
        symm::Cipher::aes_256_gcm(),
        symm::Mode::Encrypt,
        &key,
        Some(&iv),
    )
    .unwrap();
    let mut ciphertext = [0u8; 16];
    assert_eq!(enc.update(&plaintext, &mut ciphertext).unwrap(), 16);
    assert_eq!(enc.finalize(&mut []).unwrap(), 0);
    let mut tag = [0u8; 16];
    enc.get_tag(&mut tag).unwrap();
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(tag, expected_tag);

    let mut dec = symm::Crypter::new(
        symm::Cipher::aes_256_gcm(),
        symm::Mode::Decrypt,
        &key,
        Some(&iv),
    )
    .unwrap();
    let mut recovered = [0u8; 16];
    assert_eq!(dec.update(&ciphertext, &mut recovered).unwrap(), 16);
    dec.set_tag(&tag).unwrap();
    assert_eq!(dec.finalize(&mut []).unwrap(), 0);
    assert_eq!(recovered, plaintext);
}

#[test]
fn test_aes_256_gcm_authentication() {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    let aad = b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0";
    let plaintext = *b"sixteen bytes!!!";

    let mut enc = symm::Crypter::new(
        symm::Cipher::aes_256_gcm(),
        symm::Mode::Encrypt,
        &key,
        Some(&iv),
    )
    .unwrap();
    enc.aad_update(aad).unwrap();
    let mut ciphertext = [0u8; 16];
    enc.update(&plaintext, &mut ciphertext).unwrap();
    enc.finalize(&mut []).unwrap();
    let mut tag = [0u8; 16];
    enc.get_tag(&mut tag).unwrap();

    let decrypt = |aad: &[u8], ciphertext: &[u8], tag: &[u8]| {
        let mut dec = symm::Crypter::new(
            symm::Cipher::aes_256_gcm(),
            symm::Mode::Decrypt,
            &key,
            Some(&iv),
        )
        .unwrap();
        dec.aad_update(aad).unwrap();
        let mut recovered = [0u8; 16];
        dec.update(ciphertext, &mut recovered).unwrap();
        dec.set_tag(tag).unwrap();
        dec.finalize(&mut []).map(|_| recovered)
    };

    assert_eq!(decrypt(aad, &ciphertext, &tag).unwrap(), plaintext);
    assert!(decrypt(b"a different header", &ciphertext, &tag).is_err());

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(decrypt(aad, &ciphertext, &bad_tag).is_err());

    let mut bad_ciphertext = ciphertext;
    bad_ciphertext[0] ^= 1;
    assert!(decrypt(aad, &bad_ciphertext, &tag).is_err());
}

#[test]
fn test_sign_oneshot() {
    let sk = Rsa::generate(2048).unwrap();
    let pk = sk.public_key().unwrap();

    let sk = PKey::from_rsa(sk).unwrap();
    let pk = PKey::from_rsa(pk).unwrap();

    let mut signer = Signer::new(MessageDigest::Sha256, &sk).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    let signature = signer.sign_oneshot_to_vec(b"hello").unwrap();

    let mut verifier = Verifier::new(MessageDigest::Sha256, &pk).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1).unwrap();
    assert!(verifier.verify_oneshot(&signature, b"hello").unwrap());
}

#[cfg(test)]
const MLDSA_ALGORITHMS: [Algorithm; 3] =
    [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87];

#[cfg(test)]
pub(crate) fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn test_mldsa_sign_verify() {
    for algorithm in MLDSA_ALGORITHMS {
        let (pk, sk) = MlDsaPrivateKey::generate(algorithm).unwrap();
        let mut sig = sk.sign(b"hello world").unwrap();
        assert_eq!(sig.len(), algorithm.signature_bytes());
        pk.verify(b"hello world", &sig).unwrap();

        assert!(pk.verify(b"another message", &sig).is_err());
        sig[5] ^= 1;
        assert!(pk.verify(b"hello world", &sig).is_err());
        assert!(pk.verify(b"hello world", &sig[..sig.len() - 1]).is_err());
        assert!(pk.verify(b"hello world", &[]).is_err());
    }
}

#[test]
fn test_mldsa_seed_roundtrip() {
    for algorithm in MLDSA_ALGORITHMS {
        let generated_seed = *MlDsaPrivateKey::generate(algorithm).unwrap().1.seed_bytes();

        for seed in [[0x42; PRIVATE_KEY_SEED_BYTES], generated_seed] {
            let sk = MlDsaPrivateKey::from_seed(algorithm, &seed).unwrap();
            assert_eq!(sk.seed_bytes(), &seed);
            let pk = sk.public_key().unwrap();

            let rebuilt = MlDsaPrivateKey::from_seed(algorithm, &seed).unwrap();
            assert_eq!(
                rebuilt.public_key().unwrap().to_bytes().unwrap(),
                pk.to_bytes().unwrap()
            );
            pk.verify(b"roundtrip", &rebuilt.sign(b"roundtrip").unwrap())
                .unwrap();
        }
    }
}

#[test]
fn test_mldsa_clone_private_key() {
    for algorithm in MLDSA_ALGORITHMS {
        let (pk, sk) = MlDsaPrivateKey::generate(algorithm).unwrap();
        let sk2 = sk.clone();
        assert_eq!(sk2.algorithm(), sk.algorithm());
        assert_eq!(sk2.seed_bytes(), sk.seed_bytes());

        let sig = sk2.sign(b"cloned").unwrap();
        pk.verify(b"cloned", &sig).unwrap();
    }
}

#[test]
fn test_mldsa_public_from_private() {
    for algorithm in MLDSA_ALGORITHMS {
        let (pk, sk) = MlDsaPrivateKey::generate(algorithm).unwrap();
        assert_eq!(sk.algorithm(), algorithm);
        assert_eq!(pk.algorithm(), algorithm);

        let derived = sk.public_key().unwrap();
        assert_eq!(derived.algorithm(), algorithm);
        assert_eq!(derived.to_bytes().unwrap(), pk.to_bytes().unwrap());
    }
}

#[test]
fn test_mldsa_keygen_nist_vectors() {
    // Seed and public key digest, from the NIST ACVP vectors that BoringSSL tests against.
    let vectors: [(Algorithm, [u8; 32], [u8; 32]); 3] = [
        (
            Algorithm::MlDsa44,
            hex("d71361c000f9a7bc99dfb425bcb6bb27c32c36ab444ff3708b2d93b4e66d5b5b"),
            hex("451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34"),
        ),
        (
            Algorithm::MlDsa65,
            hex("70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c"),
            hex("646b26b8d09dbc9e865b6a006c693a3127b065e62fab5fbe8b159c416462feb6"),
        ),
        (
            Algorithm::MlDsa87,
            hex("19e9e5efe0c1549ddb1d72213636d16fe2faeb2428257004ae464094ca536a66"),
            hex("829d88fd913cca728ff6b19bce6ced5e73a54347411db3a4a75f563f18c1ce65"),
        ),
    ];

    for (algorithm, seed, expected_digest) in vectors {
        let sk = MlDsaPrivateKey::from_seed(algorithm, &seed).unwrap();
        let pk_bytes = sk.public_key().unwrap().to_bytes().unwrap();
        assert_eq!(pk_bytes.len(), algorithm.public_key_bytes());
        assert_eq!(Sha256::hash(&pk_bytes), expected_digest);
    }
}

#[test]
fn test_mldsa_signatures_are_randomized() {
    let (pk, sk) = MlDsaPrivateKey::generate(Algorithm::MlDsa65).unwrap();
    let sig1 = sk.sign(b"hedged").unwrap();
    let sig2 = sk.sign(b"hedged").unwrap();
    assert_ne!(sig1, sig2);
    pk.verify(b"hedged", &sig1).unwrap();
    pk.verify(b"hedged", &sig2).unwrap();
}

#[test]
fn test_mldsa_debug_redacts_seed() {
    let (_, sk) = MlDsaPrivateKey::generate(Algorithm::MlDsa44).unwrap();
    let repr = format!("{:?}", sk);
    assert!(repr.contains("redacted"));
    assert!(!repr.contains(&format!("{:?}", sk.seed_bytes())));
}

#[test]
fn test_mldsa_algorithm_sizes() {
    assert_eq!(Algorithm::MlDsa44.public_key_bytes(), 1312);
    assert_eq!(Algorithm::MlDsa44.signature_bytes(), 2420);
    assert_eq!(Algorithm::MlDsa65.public_key_bytes(), 1952);
    assert_eq!(Algorithm::MlDsa65.signature_bytes(), 3309);
    assert_eq!(Algorithm::MlDsa87.public_key_bytes(), 2592);
    assert_eq!(Algorithm::MlDsa87.signature_bytes(), 4627);
}

#[test]
fn test_mldsa_public_key_bytes_roundtrip() {
    for algorithm in MLDSA_ALGORITHMS {
        let (pk, sk) = MlDsaPrivateKey::generate(algorithm).unwrap();
        let sig = sk.sign(b"roundtrip test").unwrap();

        let pk_bytes = pk.to_bytes().unwrap();
        assert_eq!(pk_bytes.len(), algorithm.public_key_bytes());

        let pk2 = MlDsaPublicKey::from_slice(algorithm, &pk_bytes).unwrap();
        assert_eq!(pk2.algorithm(), algorithm);
        assert_eq!(pk2.to_bytes().unwrap(), pk_bytes);
        pk2.verify(b"roundtrip test", &sig).unwrap();

        for other in MLDSA_ALGORITHMS {
            if other != algorithm {
                assert!(MlDsaPublicKey::from_slice(other, &pk_bytes).is_err());
            }
        }
        assert!(MlDsaPublicKey::from_slice(algorithm, &pk_bytes[1..]).is_err());
        assert!(MlDsaPublicKey::from_slice(algorithm, &[]).is_err());
    }
}
