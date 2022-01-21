use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::SecureRng;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

fn alice(rx_alice: Receiver<Vec<u8>>, m1: u64, m2: u64) -> u32 {
    let received = rx_alice.recv().unwrap();
    let pk_arr: [u8; 32] = received.try_into().unwrap();
    let pk = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&pk_arr)
        .decompress()
        .unwrap();

    0
}

fn bob(tx_bob: std::sync::mpsc::Sender<Vec<u8>>) -> u32 {
    let mut rng = SecureRng::new(OsRng);
    let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
    tx_bob.send(pk.compress().to_bytes().to_vec()).unwrap();
    
    0
}

fn main() {
    //Alice is the main thread, Bob is the thread we create.
    let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    thread::spawn(move || {
        bob(tx_bob);
    });
    alice(rx_alice, 5, 2);
}

#[cfg(test)]
mod tests {
    use super::*;
}
