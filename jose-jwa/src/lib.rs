// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

use core::fmt;

use serde::{Deserialize, Serialize};

/// Possible types of algorithms that can exist in an "alg" or "enc" descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// Algorithms used for digital signatures and MACs
    Signing(Signing),
    /// Cryptographic Algorithms for Key Management
    KeyManagement(KeyManagement),
    /// Cryptographic Algorithms for Content Encryption
    ContentEncryption(ContentEncryption),
}

impl From<Signing> for Algorithm {
    #[inline(always)]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

impl From<KeyManagement> for Algorithm {
    #[inline(always)]
    fn from(alg: KeyManagement) -> Self {
        Self::KeyManagement(alg)
    }
}

impl From<ContentEncryption> for Algorithm {
    #[inline(always)]
    fn from(alg: ContentEncryption) -> Self {
        Self::ContentEncryption(alg)
    }
}

/// Algorithms used for signing, as defined in [RFC7518] section 3.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Signing {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    Es512,

    /// HMAC using SHA-256 (Required)
    Hs256,

    /// HMAC using SHA-384 (Optional)
    Hs384,

    /// HMAC using SHA-512 (Optional)
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    Rs512,

    /// No digital signature or MAC performed (Optional)
    ///
    /// This variant is renamed as `Null` to avoid colliding with `Option::None`.
    #[serde(rename = "none")]
    Null,
}

impl fmt::Display for Signing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Cryptographic Algorithms for Key Management, as defined in [RFC7518] section 4.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyManagement {
    /// RSAES-PKCS1-v1_5
    #[serde(rename = "RSA1_5")]
    Rsa1_5,
    /// RSAES OAEP using default parameters
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// AES Key Wrap with default initial value using 128-bit key
    A128KW,
    /// AES Key Wrap with default initial value using 192-bit key
    A192KW,
    /// AES Key Wrap with default initial value using 256-bit key
    A256KW,
    /// Direct use of a shared symmetric key as the CEK
    #[serde(rename = "dir")]
    Dir,
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
    /// Key wrapping with AES GCM using 128-bit key
    #[serde(rename = "A128GCMKW")]
    A128GcmKw,
    /// Key wrapping with AES GCM using 192-bit key
    #[serde(rename = "A192GCMKW")]
    A192GcmKw,
    /// Key wrapping with AES GCM using 256-bit key
    #[serde(rename = "A256GCMKW")]
    A256GcmKw,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

impl fmt::Display for KeyManagement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Cryptographic Algorithms for Content Encryption, as defined in [RFC7518] section 5.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    /// AES GCM using 128-bit key
    #[serde(rename = "A128GCM")]
    A128Gcm,
    /// AES GCM using 192-bit key
    #[serde(rename = "A192GCM")]
    A192Gcm,
    /// AES GCM using 256-bit key
    #[serde(rename = "A256GCM")]
    A256Gcm,
}

impl fmt::Display for ContentEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Cryptographic Algorithms for Keys (Key Types), as defined in [RFC7518] section 6.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Elliptic Curve
    #[serde(rename = "EC")]
    Ec,
    /// RSA
    #[serde(rename = "RSA")]
    Rsa,
    /// Octet sequence (used to represent symmetric keys)
    #[serde(rename = "oct")]
    Oct,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Elliptic Curve names, as defined in [RFC7518] section 6.2.1.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EllipticCurve {
    /// P-256 Curve
    #[serde(rename = "P-256")]
    P256,
    /// P-384 Curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 Curve
    #[serde(rename = "P-521")]
    P521,
}

impl fmt::Display for EllipticCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// JSON Web Encryption Compression Algorithms, as defined in [RFC7518] section 7.3.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// DEFLATE
    #[serde(rename = "DEF")]
    Def,
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;
    use std::vec;

    use super::*;

    #[test]
    fn simple_roundtrip() {
        use Signing::*;

        let input = vec![
            EdDsa, Es256, Es256K, Es384, Es512, Hs256, Hs384, Hs512, Ps256, Ps384, Ps512, Rs256,
            Rs384, Rs512, Null,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["EdDSA","ES256","ES256K","ES384","ES512","HS256","HS384","HS512","PS256","PS384","PS512","RS256","RS384","RS512","none"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Signing>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn key_management_roundtrip() {
        use KeyManagement::*;

        let input = vec![
            Rsa1_5,
            RsaOaep,
            RsaOaep256,
            A128KW,
            A192KW,
            A256KW,
            Dir,
            EcdhEs,
            EcdhEsA128Kw,
            EcdhEsA192Kw,
            EcdhEsA256Kw,
            A128GcmKw,
            A192GcmKw,
            A256GcmKw,
            Pbes2Hs256A128Kw,
            Pbes2Hs384A192Kw,
            Pbes2Hs512A256Kw,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["RSA1_5","RSA-OAEP","RSA-OAEP-256","A128KW","A192KW","A256KW","dir","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A192KW","ECDH-ES+A256KW","A128GCMKW","A192GCMKW","A256GCMKW","PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<KeyManagement>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn content_encryption_roundtrip() {
        use ContentEncryption::*;

        let input = vec![
            A128CbcHs256,
            A192CbcHs384,
            A256CbcHs512,
            A128Gcm,
            A192Gcm,
            A256Gcm,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["A128CBC-HS256","A192CBC-HS384","A256CBC-HS512","A128GCM","A192GCM","A256GCM"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<ContentEncryption>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn key_type_roundtrip() {
        use KeyType::*;

        let input = vec![Ec, Rsa, Oct];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(ser, r#"["EC","RSA","oct"]"#);

        assert_eq!(
            serde_json::from_str::<Vec<KeyType>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn elliptic_curve_roundtrip() {
        use EllipticCurve::*;

        let input = vec![P256, P384, P521];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(ser, r#"["P-256","P-384","P-521"]"#);

        assert_eq!(
            serde_json::from_str::<Vec<EllipticCurve>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn compression_algorithm_roundtrip() {
        use CompressionAlgorithm::*;

        let input = vec![Def];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(ser, r#"["DEF"]"#);

        assert_eq!(
            serde_json::from_str::<Vec<CompressionAlgorithm>>(&ser)
                .expect("deserialization failed"),
            input
        );
    }
}
