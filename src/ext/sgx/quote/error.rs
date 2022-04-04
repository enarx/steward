use core::fmt::{self, Display};

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum QuoteError {
    UnsupportedQuoteVersion(u16),
    UnexpectedLength(&'static str, usize, usize),
    UnknownCertDataType,
    UnsupportedCertDataType(&'static str),
    CertChainParse(String),
}

impl Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteError::UnsupportedQuoteVersion(version) => {
                write!(f, "Unsupported quote version {:?}", version)
            }
            QuoteError::UnexpectedLength(ident, actual, expected) => {
                write!(
                    f,
                    "The {} slice had an unexpected length of {}, expected {}",
                    ident, actual, expected
                )
            }
            QuoteError::UnknownCertDataType => {
                write!(f, "Unknown cert data type",)
            }
            QuoteError::UnsupportedCertDataType(message) => {
                write!(f, "Unsupported certificate data type: {}", message)
            }
            QuoteError::CertChainParse(message) => {
                write!(f, "Certificate chain parse error: {}", message)
            }
        }
    }
}
