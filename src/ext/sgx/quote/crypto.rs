use der::{asn1::UIntBytes, Encodable, Sequence};

/// EC KT-I Public Key, the x-coordinate followed by
/// the y-coordinate (on the RFC 6090P-256 curve),
/// 2 x 32 bytes.
/// A.4, Table 7
#[derive(Clone, Debug)]
#[repr(C)]
pub struct EcdsaPubKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// ECDSA signature, the r component followed by the
/// s component, 2 x 32 bytes.
/// A.4, Table 6
#[derive(Clone, Debug)]
#[repr(C)]
pub struct EcdsaP256Sig {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl EcdsaP256Sig {
    // The size of the buffer the DER encoded signature will occupy.
    const DER_ENCODED_LEN: usize = 72;

    /// Converts the concatenated signature to a DER signature.
    ///
    /// Returns the buffer containing the DER and its length.
    pub fn to_der(&self) -> Result<([u8; Self::DER_ENCODED_LEN], usize), der::Error> {
        /// ECDSA-Sig-Value ::= SEQUENCE {
        ///    r INTEGER,
        ///    s INTEGER
        /// }
        #[derive(Clone, Debug, Sequence)]
        struct EcdsaSig<'a> {
            r: UIntBytes<'a>,
            s: UIntBytes<'a>,
        }

        let es = EcdsaSig {
            r: UIntBytes::new(&self.r)?,
            s: UIntBytes::new(&self.s)?,
        };

        let mut buffer = [0; Self::DER_ENCODED_LEN];
        let mut encoder = der::Encoder::new(&mut buffer);
        es.encode(&mut encoder)?;
        let len = encoder.finish()?.len();
        Ok((buffer, len))
    }
}
