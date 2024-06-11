// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

use core::ops::{Add, AddAssign, Sub, SubAssign};

use codec::{Decode, Encode, EncodeLike};
use scale_info::TypeInfo;
use sp_runtime_interface::pass_by::{Inner, PassBy, PassByInner};

use confidential_assets::{CipherText, CompressedCipherText};

type CompressedBytes = [u8; 64];

/// Host type for `CompressedCipherText`.
#[derive(TypeInfo, Encode, Decode, Copy, Clone, Debug, PartialEq, Eq)]
pub struct HostCipherText(pub CompressedBytes);

impl Default for HostCipherText {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl HostCipherText {
    pub fn compressed(&self) -> CompressedCipherText {
        CompressedCipherText::from_slice(&self.0[..])
    }

    pub fn decompress(&self) -> CipherText {
        self.compressed().decompress()
    }
}

impl EncodeLike<HostCipherText> for CompressedCipherText {}

impl PassBy for HostCipherText {
    type PassBy = Inner<Self, CompressedBytes>;
}

impl PassByInner for HostCipherText {
    type Inner = CompressedBytes;

    fn into_inner(self) -> CompressedBytes {
        self.0
    }
    fn inner(&self) -> &CompressedBytes {
        &self.0
    }
    fn from_inner(inner: CompressedBytes) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "std")]
impl Add for HostCipherText {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let val = self.compressed() + rhs.compressed();
        HostCipherText(val.to_bytes())
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
        let val = self.compressed() - rhs.compressed();
        HostCipherText(val.to_bytes())
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
        Self(other.to_bytes())
    }
}

impl From<CipherText> for HostCipherText {
    fn from(other: CipherText) -> Self {
        Self(other.compress().to_bytes())
    }
}
