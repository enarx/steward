use std::fs;
use std::io;
use hex_literal::hex;
use sha2::{Sha256, Digest};

#[test]
fn validate_milan_cert() {
    let mut file = fs::File::open("certs/ask_ark_milan.cert").unwrap();
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("Failed to read cert file");
    assert_eq!(hasher.finalize()[..], hex!("f3315952a077b37c3c7c58aea544a16fc62fe5a06185b33c86a518658bb2086b"))
}

#[test]
fn validate_rome_cert() {
    let mut file = fs::File::open("certs/ask_ark_rome.cert").unwrap();
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("Failed to read cert file");
    assert_eq!(hasher.finalize()[..], hex!("9d7e6b96377ab614e2182e0aae0dcde597019fca23716423f4b902f5dc15c0a6"))
}

#[test]
fn validate_naples_cert() {
    let mut file = fs::File::open("certs/ask_ark_naples.cert").unwrap();
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("Failed to read cert file");
    assert_eq!(hasher.finalize()[..], hex!("4629ccff0b7dbe64de42925f7d6c97afc60143b4ad027cb6c51e50bfb35ccbf9"))
}
