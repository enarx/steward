use crate::ext::sgx::quote::error::QuoteError;

use sgx::ReportBody;

use std::mem::{size_of, transmute};

/// Try to cast a byte slice into a statically sized type.
pub fn slice_cast<'a, const SIZE: usize>(
    identifier: &'static str,
    slice: &'a [u8],
) -> Result<&'a [u8; SIZE], QuoteError> {
    slice
        .try_into()
        .map_err(|_| QuoteError::UnexpectedLength(identifier, slice.len(), SIZE))
}

pub fn report_body_as_bytes(body: &ReportBody) -> &[u8; size_of::<ReportBody>()] {
    // SAFETY: This is safe because the returning slice should always have an alignment of 1 byte.
    unsafe { transmute(body) }
}

pub fn report_body_from_bytes(body: [u8; size_of::<ReportBody>()]) -> ReportBody {
    // SAFETY: This is safe because we are casting owned bytes to a owned well-defined struct.
    unsafe { transmute(body) }
}
