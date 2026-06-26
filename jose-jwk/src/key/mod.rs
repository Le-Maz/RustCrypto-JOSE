// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK key material.

use serde::{Deserialize, Serialize};

mod ec_key;
mod oct_key;
mod okp_key;
mod rsa_key;

pub use self::ec_key::{EcCurves, EcKey};
pub use self::oct_key::OctKey;
pub use self::okp_key::{OkpCurves, OkpKey};
pub use self::rsa_key::{RsaKey, RsaOptional, RsaOtherPrimes, RsaPrivate};

/// A key type that can be contained in a JWK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", tag = "kty")]
#[non_exhaustive]
pub enum Key {
    /// An elliptic-curve key.
    Ec(EcKey),

    /// An RSA key.
    Rsa(RsaKey),

    /// A symmetric key.
    #[serde(rename = "oct")]
    Oct(OctKey),

    /// A CFRG-curve key.
    Okp(OkpKey),
}

impl From<EcKey> for Key {
    #[inline(always)]
    fn from(key: EcKey) -> Self {
        Self::Ec(key)
    }
}

impl From<RsaKey> for Key {
    #[inline(always)]
    fn from(key: RsaKey) -> Self {
        Self::Rsa(key)
    }
}

impl From<OctKey> for Key {
    #[inline(always)]
    fn from(key: OctKey) -> Self {
        Self::Oct(key)
    }
}

impl From<OkpKey> for Key {
    #[inline(always)]
    fn from(key: OkpKey) -> Self {
        Self::Okp(key)
    }
}
