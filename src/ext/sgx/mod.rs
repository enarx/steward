mod quote;

use crate::crypto::*;
use quote::{cast::report_body_as_bytes, Quote, QuoteBody};

use std::fmt::Debug;

use anyhow::{anyhow, Context, Result};
use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
use const_oid::ObjectIdentifier;
use der::Decodable;
use pkcs8::AlgorithmIdentifier;
use x509::{ext::Extension, request::CertReqInfo, Certificate, TbsCertificate};

use super::ExtVerifier;

#[derive(Clone, Debug)]
pub struct Sgx([Certificate<'static>; 1]);

impl Default for Sgx {
    fn default() -> Self {
        Self([Certificate::from_der(Self::ROOT).unwrap()])
    }
}

impl Sgx {
    const ROOT: &'static [u8] = include_bytes!("root.der");

    fn trusted<'c>(&'c self, chain: &'c [Certificate<'c>]) -> Result<&'c TbsCertificate<'c>> {
        let mut signer = &self.0[0].tbs_certificate;
        for cert in self.0.iter().chain(chain.iter()) {
            signer = signer.verify_crt(cert)?;
        }

        Ok(signer)
    }
}

impl ExtVerifier for Sgx {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    const ATT: bool = true;

    fn verify(&self, cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("snp extension cannot be critical"));
        }

        // Decode the evidence.
        let quote =
            Quote::try_from(ext.extn_value).map_err(|e| anyhow!("quote parsing error: {}", e))?;
        let chain = match &quote.body {
            QuoteBody::V3(quote) => quote.sig_data().qe_cert_chain().map_err(|e| anyhow!(e))?,
        };
        let chain = chain
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;

        // Validate the PCK.
        let pck = self.trusted(&chain).unwrap();

        // Force certs to have the same key type as the PCK.
        //
        // A note about this check is in order. We don't want to build crypto
        // algorithm negotiation into this protocol. Not only is it complex
        // but it is also subject to downgrade attacks. For example, if the
        // weakest link in the certificate chain is a P384 key and the
        // attacker downgrades the negotiation to P256, it has just weakened
        // security for the whole chain.
        //
        // We solve this by using forcing the certification request to have
        // the same key type as the PCK. This means we have no worse security
        // than whatever Intel chose for the PCK.
        //
        // Additionally, we do this check early to be defensive.
        if cri.public_key.algorithm != pck.subject_public_key_info.algorithm {
            return Err(anyhow!("sgx pck algorithm mismatch"));
        }

        // Extract the quote and its signature.
        let (report, (signature, signature_len)) = match &quote.body {
            QuoteBody::V3(quote) => {
                let report = report_body_as_bytes(quote.sig_data().qe_report());
                let signature = quote
                    .sig_data()
                    .qe_report_sig()
                    .to_der()
                    .context("sgx quote signature parse error")?;

                (report, signature)
            }
        };

        pck.verify_raw(
            report,
            AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            &signature[..signature_len],
        )
        .context("sgx quote contains invalid signature")?;

        // TODO: validate more fields with the verify function
        quote.verify()?;

        if !dbg {
            // TODO: Validate that the certification request came from an SGX enclave.
        }

        Ok(true)
    }
}
