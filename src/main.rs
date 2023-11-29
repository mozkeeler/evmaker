extern crate base64;
extern crate pem;
extern crate sha2;
extern crate x509_parser;

use oid_registry::{Oid, OidRegistry};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

fn oid_to_abbrev(oid: &Oid) -> String {
    oid2abbrev(oid, &OidRegistry::default())
        .map(|s| s.to_string())
        .unwrap_or(oid.to_string())
}

fn reverse_dn(dn: &X509Name) -> String {
    let mut rdns: Vec<String> = Vec::new();
    for rdn in dn.iter() {
        let mut avas: Vec<String> = Vec::new();
        for ava in rdn.iter() {
            let mut value = ava.as_str().expect("ava should be displayable").to_string();
            if value.contains(',') {
                value = format!("\"{value}\"");
            }
            let typ = oid_to_abbrev(ava.attr_type());
            avas.push(format!("{typ}={value}"));
        }
        rdns.push(avas.join(","));
    }
    rdns.into_iter().rev().collect::<Vec<String>>().join(",")
}

fn print_hash(der: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let hash = hasher.finalize().to_vec();
    print!("    {{ ");
    for b in &hash[0..11] {
        print!("0x{:02X}, ", b);
    }
    println!();
    print!("      ");
    for b in &hash[11..22] {
        print!("0x{:02X}, ", b);
    }
    println!();
    print!("      ");
    for b in &hash[22..31] {
        print!("0x{:02X}, ", b);
    }
    println!("0x{:02X} }},", hash[31]);
}

fn print_subject(subject: &X509Name) {
    let base64 = base64::encode(subject.as_raw());
    let base64_chunks = base64.as_bytes().chunks(64);
    let mut first = true;
    for chunk in base64_chunks {
        if !first {
            println!();
        }
        print!(
            "    \"{}\"",
            std::str::from_utf8(chunk).expect("shouldn't have utf8 problems")
        );
        first = false;
    }
    println!(",");
}

fn print_one_certificate(path: &str) {
    let maybe_pem = std::fs::read(path).expect("file should exist");
    let der = match pem::parse(&maybe_pem) {
        Ok(decoded) => decoded.contents,
        Err(_) => maybe_pem,
    };
    let cert = X509Certificate::from_der(&der)
        .expect("file should be x509 certificate")
        .1;
    println!("  {{");
    println!("    // {}", reverse_dn(cert.subject()));
    println!("    \"2.23.140.1.1\",");
    println!("    \"CA/Browser Forum EV OID\",");
    print_hash(&der);
    print_subject(cert.subject());
    println!("    \"{}\",", base64::encode(cert.raw_serial()));
    println!("  }},");
}

fn main() {
    for path in std::env::args().skip(1) {
        print_one_certificate(&path);
    }
}
