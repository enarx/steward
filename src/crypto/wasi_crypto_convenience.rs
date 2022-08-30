use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SECP_256_R_1 as P256, SECP_384_R_1 as P384,
};
use const_oid::ObjectIdentifier;

pub fn oid_to_wcrypto_string(oid: ObjectIdentifier) -> &'static str {
    match oid {
        ECDSA_WITH_SHA_256 => "ECDSA_P256_SHA256",
        P256 => "ECDSA_P256_SHA256",
        ECDSA_WITH_SHA_384 => "ECDSA_P384_SHA384",
        P384 => "ECDSA_P384_SHA384",
        x => {
            eprintln!("Unknown OID {:?}", x);
            panic!("Unknown OID {:?}", x);
            ""
        }
    }
}

pub fn wcrypto_string_to_key_oid(algo: &str) -> ObjectIdentifier {
    match algo {
        "ECDSA_P256_SHA256" => P256,
        "ECDSA_P384_SHA384" => P384,
        x => {
            eprintln!("Unknown string {:?}", x);
            panic!("Unknown string {:?}", x);
            unreachable!()
        }
    }
}

pub fn wcrypto_string_to_hash_oid(algo: &str) -> ObjectIdentifier {
    match algo {
        "ECDSA_P256_SHA256" => ECDSA_WITH_SHA_256,
        "ECDSA_P384_SHA384" => ECDSA_WITH_SHA_384,
        x => {
            eprintln!("Unknown string {:?}", x);
            panic!("Unknown string {:?}", x);
            unreachable!()
        }
    }
}
