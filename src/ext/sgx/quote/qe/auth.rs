use super::super::{FromBytes, ParseBytes, Steal};

use std::array::TryFromSliceError;

#[derive(Clone, Debug)]
pub struct Data<'a>(&'a [u8]);

impl<'a> AsRef<[u8]> for Data<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> FromBytes<'a> for Data<'a> {
    type Error = TryFromSliceError;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (len, bytes) = bytes.parse()?;
        let (buf, bytes) = bytes.steal(u16::from_le_bytes(len).into())?;
        Ok((Self(buf), bytes))
    }
}
