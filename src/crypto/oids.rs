use der::asn1::ObjectIdentifier;

pub const RSA_ES_PKCS1_V1_5: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");
pub const RSA_SSA_PSS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.10");
pub const RSA_MGF1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.8");
pub const SHA256: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1");
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.2");
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.3");

pub const ECPUBKEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
pub const NISTP256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");
pub const NISTP384: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");
//pub const ECDSA_SHA224: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.1");
pub const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.2");
pub const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");
//pub const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.4");
