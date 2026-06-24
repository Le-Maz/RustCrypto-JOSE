// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Provides conditional zeroization wrappers based on the `secret` feature.
//!
//! When the `secret` feature is enabled, these structures will securely clear
//! memory. When disabled, they act as transparent, no-op wrappers to avoid
//! unnecessary overhead.

use core::ops::{Deref, DerefMut};

#[cfg(feature = "secret")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A trait for types that can be conditionally zeroized.
pub trait MaybeZeroize {
    /// Performs zeroization if the `secret` feature is enabled.
    ///
    /// If the `secret` feature is disabled, this is a no-op.
    fn maybe_zeroize(&mut self);
}

#[cfg(feature = "secret")]
impl<T> MaybeZeroize for T
where
    T: Zeroize,
{
    fn maybe_zeroize(&mut self) {
        self.zeroize();
    }
}

#[cfg(not(feature = "secret"))]
impl<T> MaybeZeroize for T {
    fn maybe_zeroize(&mut self) {}
}

/// A wrapper type that conditionally zeroizes its contents when dropped.
///
/// This struct behaves similarly to `zeroize::Zeroizing`, ensuring that the
/// wrapped data is cleared from memory when it goes out of scope, provided
/// the `secret` feature flag is active.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaybeZeroizing<T>(T)
where
    T: MaybeZeroize;

#[cfg(feature = "secret")]
impl<T> Zeroize for MaybeZeroizing<T>
where
    T: MaybeZeroize + Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "secret")]
impl<T> ZeroizeOnDrop for MaybeZeroizing<T> where T: MaybeZeroize {}

impl<T> Drop for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    /// Drops the wrapper, executing zeroization logic if the `secret` feature is enabled.
    fn drop(&mut self) {
        self.maybe_zeroize();
    }
}

impl<T> From<T> for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: AsRef<U>, U: ?Sized> AsRef<U> for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T: AsMut<U>, U: ?Sized> AsMut<U> for MaybeZeroizing<T>
where
    T: MaybeZeroize,
{
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}
