// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::array::TryFromSliceError;

pub trait Steal<T> {
    fn steal(&self, len: usize) -> Result<(&[T], &[T]), TryFromSliceError>;
}

impl<T> Steal<T> for [T] {
    fn steal(&self, len: usize) -> Result<(&[T], &[T]), TryFromSliceError> {
        if self.len() < len {
            let _: &[u8; 1] = [0u8; 0][..].try_into()?;
            unreachable!();
        }

        Ok(self.split_at(len))
    }
}

pub trait FromBytes<'a>: Sized {
    type Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error>;
}

impl<'a, const N: usize> FromBytes<'a> for &'a [u8; N] {
    type Error = TryFromSliceError;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (lhs, rhs) = bytes.steal(N)?;
        Ok((lhs.try_into().unwrap(), rhs))
    }
}

impl<'a, const N: usize> FromBytes<'a> for [u8; N] {
    type Error = TryFromSliceError;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        bytes.parse().map(|(l, r): (&[u8; N], _)| (*l, r))
    }
}

pub trait ParseBytes<'a, T: FromBytes<'a>> {
    type Error;

    fn parse(self) -> Result<(T, &'a [u8]), T::Error>;
}

impl<'a, T: FromBytes<'a>> ParseBytes<'a, T> for &'a [u8] {
    type Error = T::Error;

    fn parse(self) -> Result<(T, &'a [u8]), Self::Error> {
        T::from_bytes(self)
    }
}
