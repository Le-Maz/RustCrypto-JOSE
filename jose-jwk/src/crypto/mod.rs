// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cryptographic primitives for JWK

mod keyinfo;
mod kind;
mod parsed_key;
mod rsa;

pub use keyinfo::KeyInfo;
pub use kind::Kind;
pub use parsed_key::ParsedKey;

use core::convert::Infallible;

/// An error related to key material.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Error {
    /// The inputs are invalid.
    #[default]
    Invalid,

    /// The private key is unknown.
    NotPrivate,

    /// An algorithm mismatch occurred.
    AlgMismatch,

    /// The specified criteria are unsupported.
    Unsupported,
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
