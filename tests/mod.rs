use hex_literal::hex;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;

#[test]
fn validate_milan_cert() {
    let mut file = fs::File::open("certs/Milan.pem").unwrap();
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("Failed to read cert file");
    assert_eq!(
        hasher.finalize()[..],
        hex!("22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6")
    )
}

#[test]
fn validate_genoa_cert() {
    let mut file = fs::File::open("certs/Genoa.pem").unwrap();
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("Failed to read cert file");
    assert_eq!(
        hasher.finalize()[..],
        hex!("125e5d458b0f93d6b2006a2175df52cf988fff4d0e7e220cd0186d402bf2c33f")
    )
}
