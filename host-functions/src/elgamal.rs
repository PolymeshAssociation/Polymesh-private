// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

use core::ops::{Add, AddAssign, Sub, SubAssign};

use codec::{Decode, Encode, EncodeLike};
use scale_info::TypeInfo;
use sp_runtime_interface::pass_by::{Inner, PassBy, PassByInner};

use confidential_assets::{CipherText, CompressedCipherText};

/// Host type for `CompressedCipherText`.
#[derive(TypeInfo, Encode, Decode, Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct HostCipherText(pub CompressedCipherText);

impl EncodeLike<HostCipherText> for CompressedCipherText {}

impl PassBy for HostCipherText {
    type PassBy = Inner<Self, [u8; 64]>;
}

impl PassByInner for HostCipherText {
    type Inner = [u8; 64];

    fn into_inner(self) -> [u8; 64] {
        self.0.to_bytes()
    }
    fn inner(&self) -> &[u8; 64] {
        self.0.as_bytes()
    }
    fn from_inner(inner: [u8; 64]) -> Self {
        Self(CompressedCipherText::from_slice(&inner[..]))
    }
}

#[cfg(feature = "std")]
impl Add for HostCipherText {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        HostCipherText(self.0 + rhs.0)
    }
}

#[cfg(not(feature = "std"))]
impl Add for HostCipherText {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        crate::native_confidential_assets::cipher_add(self, rhs)
    }
}

impl AddAssign for HostCipherText {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

#[cfg(feature = "std")]
impl Sub for HostCipherText {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        HostCipherText(self.0 - rhs.0)
    }
}

#[cfg(not(feature = "std"))]
impl Sub for HostCipherText {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        crate::native_confidential_assets::cipher_sub(self, rhs)
    }
}

impl SubAssign for HostCipherText {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl From<CompressedCipherText> for HostCipherText {
    fn from(other: CompressedCipherText) -> Self {
        Self(other)
    }
}

impl From<CipherText> for HostCipherText {
    fn from(other: CipherText) -> Self {
        Self(other.compress())
    }
}
