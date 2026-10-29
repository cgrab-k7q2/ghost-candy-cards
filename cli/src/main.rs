//! candy-cli: print Ghost Candy Cards and prove card ownership for a claim.
//!
//!   candy-cli new <n>                     -> one line per card: "<secret_hex> <point_hex>"
//!   candy-cli nonce                       -> "<r_hex> <R_hex>"   (keep r secret, use once)
//!   candy-cli respond <s> <r> <e>         -> "<z_hex>"            z = r + e*s
//!   candy-cli verify <P> <R> <z> <e>      -> "ok" | "bad"         z*G == R + e*P
//!   candy-cli challenge <component_hex> <P> <R> <outputs_cbor_hex>  -> "<e_hex>" (same hash as the template)
//!   candy-cli selftest                    -> end-to-end check of the maths, incl. a front-running attempt
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ghost-candy-cards/v1";

fn scalar(h: &str) -> Scalar {
    let b: [u8; 32] = hex::decode(h).expect("hex").try_into().expect("32 bytes");
    Option::from(Scalar::from_canonical_bytes(b)).expect("canonical scalar")
}
fn point(h: &str) -> curve25519_dalek::RistrettoPoint {
    let b: [u8; 32] = hex::decode(h).expect("hex").try_into().expect("32 bytes");
    CompressedRistretto(b).decompress().expect("valid ristretto point")
}
fn challenge(component: &[u8], p: &[u8], r: &[u8], outputs: &[u8]) -> Scalar {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(component);
    h.update(p);
    h.update(r);
    h.update(outputs);
    let mut e: [u8; 32] = h.finalize().into();
    e[31] &= 0x0f;
    Option::from(Scalar::from_canonical_bytes(e)).unwrap()
}
fn verify(p: &curve25519_dalek::RistrettoPoint, r: &curve25519_dalek::RistrettoPoint, z: &Scalar, e: &Scalar) -> bool {
    z * G == r + e * p
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("new") => {
            let n: usize = a[2].parse().unwrap();
            for _ in 0..n {
                let s = Scalar::random(&mut OsRng);
                println!("{} {}", hex::encode(s.as_bytes()), hex::encode((s * G).compress().as_bytes()));
            }
        },
        Some("nonce") => {
            let r = Scalar::random(&mut OsRng);
            println!("{} {}", hex::encode(r.as_bytes()), hex::encode((r * G).compress().as_bytes()));
        },
        Some("respond") => {
            let z = scalar(&a[3]) + scalar(&a[4]) * scalar(&a[2]);
            println!("{}", hex::encode(z.as_bytes()));
        },
        Some("verify") => {
            let ok = verify(&point(&a[2]), &point(&a[3]), &scalar(&a[4]), &scalar(&a[5]));
            println!("{}", if ok { "ok" } else { "bad" });
            std::process::exit(if ok { 0 } else { 1 });
        },
        Some("challenge") => {
            let c = hex::decode(&a[2]).unwrap();
            let e = challenge(&c, &hex::decode(&a[3]).unwrap(), &hex::decode(&a[4]).unwrap(), &hex::decode(&a[5]).unwrap());
            println!("{}", hex::encode(e.as_bytes()));
        },
        Some("selftest") => selftest(),
        _ => eprintln!("usage: candy-cli new|nonce|respond|verify|challenge|selftest"),
    }
}

fn selftest() {
    let component = [7u8; 32];
    let s = Scalar::random(&mut OsRng);
    let p = s * G;
    let honest_outputs = b"cbor(outputs to the kid's stealth address)";
    let r = Scalar::random(&mut OsRng);
    let big_r = r * G;
    let e = challenge(&component, p.compress().as_bytes(), big_r.compress().as_bytes(), honest_outputs);
    let z = r + e * s;
    assert!(verify(&p, &big_r, &z, &e), "honest claim must verify");
    println!("honest claim: ok");

    // A watcher copies (P, R, z) but swaps in outputs paying themselves.
    let thief_outputs = b"cbor(outputs to the thief)";
    let e2 = challenge(&component, p.compress().as_bytes(), big_r.compress().as_bytes(), thief_outputs);
    assert!(!verify(&p, &big_r, &z, &e2), "copied proof must fail with different outputs");
    println!("front-run with swapped outputs: rejected");

    // Same proof replayed against another bowl.
    let e3 = challenge(&[9u8; 32], p.compress().as_bytes(), big_r.compress().as_bytes(), honest_outputs);
    assert!(!verify(&p, &big_r, &z, &e3), "proof must be bound to one component");
    println!("replay on another bowl: rejected");

    // Wrong card secret.
    let z_bad = r + e * Scalar::random(&mut OsRng);
    assert!(!verify(&p, &big_r, &z_bad, &e), "wrong secret must fail");
    println!("wrong card secret: rejected");
    // Challenge is canonical and below 2^252.
    assert!(e.as_bytes()[31] <= 0x0f);
    println!("challenge canonical: ok");
}
