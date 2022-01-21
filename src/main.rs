use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::Enrichable;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

fn alice(tx_alice: Sender<Vec<u8>>, rx_alice: Receiver<Vec<u8>>, m1: u64, m2: u64) -> u32 {
    let mut rng = SecureRng::new(OsRng);
    let received = rx_alice.recv().unwrap();
    let pk = bincode::deserialize(&received).unwrap();

    //TODO: Move this outside of Alice. Alice should eventually just have two ciphertexts.
    let m1_curve = &Scalar::from(m1) * &RISTRETTO_BASEPOINT_POINT;

    let m2_curve = &Scalar::from(m2) * &RISTRETTO_BASEPOINT_POINT;

    let c1 = CurveElGamal::encrypt(&m1_curve, &pk, &mut rng);
    let c2 = CurveElGamal::encrypt(&m2_curve, &pk, &mut rng);

    let c1c2 = &c1 + &c2;
    let encoded: Vec<u8> = bincode::serialize(&c1c2).unwrap();
    tx_alice.send(encoded).unwrap();
    thread::sleep(Duration::from_millis(10));

    0
}

fn bob(tx_bob: Sender<Vec<u8>>, rx_bob: Receiver<Vec<u8>>) -> u32 {
    let mut rng = SecureRng::new(OsRng);
    let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

    tx_bob.send(bincode::serialize(&pk).unwrap()).unwrap();
    let received = rx_bob.recv().unwrap();
    let ciphertext: scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext =
        bincode::deserialize(&received).unwrap();

    let plain = CurveElGamal::decrypt(&ciphertext.enrich(&pk), &sk);
    assert_eq!(plain, &Scalar::from(7u64) * &RISTRETTO_BASEPOINT_POINT);
    0
}

fn main() {
    //Alice is the main thread, Bob is the thread we create.
    let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    thread::spawn(move || {
        bob(tx_bob, rx_bob);
    });

    alice(tx_alice, rx_alice, 5, 2);
}

#[cfg(test)]
mod tests {
    use super::*;
}
