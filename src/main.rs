use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt::cryptosystems::paillier::Paillier;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::Enrichable;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

const L: u32 = 16;

fn alice(tx_alice: Sender<Vec<u8>>, rx_alice: Receiver<Vec<u8>>, m1: u64, m2: u64) -> u32 {
    let mut rng = SecureRng::new(OsRng);
    let received = rx_alice.recv().unwrap();
    let pk = bincode::deserialize(&received).unwrap();

    //TODO: Move this outside of Alice. Alice should eventually just have two ciphertexts.
    let m1_curve = &Scalar::from(m1) * &RISTRETTO_BASEPOINT_POINT;
    let m2_curve = &Scalar::from(m2) * &RISTRETTO_BASEPOINT_POINT;
    let power_2_l_curve = &Scalar::from(u32::pow(2, L)) * &RISTRETTO_BASEPOINT_POINT;

    let a = CurveElGamal::encrypt(&m1_curve, &pk, &mut rng);
    let b = CurveElGamal::encrypt(&m2_curve, &pk, &mut rng);

    let power_2_l_encrypted = CurveElGamal::encrypt(&power_2_l_curve, &pk, &mut rng);

    //Improvement from paper
    let delta: bool = rand::random();
    let s: i32 = match delta {
        false => 1,
        true => -1,
    };
    //Magic number 1 since they need to be unencrypted.
    cumulative_power_two(1, std::ops::Sub::sub, s);

    let mut encrypted_t: Vec<RistrettoPoint> = vec![];
    for i in 0..L {
        let received = rx_alice.recv().unwrap();
        encrypted_t.push(deserialize(&received).unwrap());
    }
    0
}

fn bob(tx_bob: Sender<Vec<u8>>, rx_bob: Receiver<Vec<u8>>) -> u32 {
    let mut rng = SecureRng::new(OsRng);
    let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

    tx_bob.send(serialize(&pk).unwrap()).unwrap();
    //Improvement from paper
    let vec = cumulative_power_two(2, std::ops::Add::add, 0);
    for i in (0..16).rev() {
        let ciphertext = CurveElGamal::encrypt(&vec[i], &pk, &mut rng);
        tx_bob.send(serialize(&ciphertext).unwrap()).unwrap();
    }
    0
}
//TODO: Look into the use of closure here again.
fn cumulative_power_two<F>(plain_number: u32, f: F, s: i32) -> Vec<RistrettoPoint>
where
    F: Fn(i32, i32) -> i32,
{
    let nuber_bin = format!("{:016b}", plain_number);
    let mut vals: Vec<i32> = vec![0];
    let mut messages: Vec<RistrettoPoint> = vec![];
    for (i, bit) in nuber_bin.chars().rev().enumerate() {
        let plaintext: i32 = match bit {
            '0' => 0,
            '1' => 1,
            _ => panic!("Error: Bit in binary representation is not 0 or 1"),
        };
        vals.push(vals[i] + plaintext * i32::pow(2, i as u32));
        
        //there may be a problem here, due to the fact that subtractions can result in negative values.
        let result = f(s, f(plaintext, vals[i]));
        let plaintext_encoded: RistrettoPoint;
        if result < 0 {
            plaintext_encoded = - &Scalar::from(result.abs() as u32) * &RISTRETTO_BASEPOINT_POINT;
        }
        else {
            plaintext_encoded = &Scalar::from(result as u32) * &RISTRETTO_BASEPOINT_POINT;
        }
        messages.push(plaintext_encoded);
    }
    messages
}

fn main() {
    //Alice is the main thread, Bob is the thread we create.
    let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    thread::spawn(move || {
        bob(tx_bob, rx_bob);
    });

    alice(tx_alice, rx_alice, 25, 25);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]

    fn additive_homomorphic() {
        let a = &Scalar::from(5u64) * &RISTRETTO_BASEPOINT_POINT;
        let b = &Scalar::from(5u64) * &RISTRETTO_BASEPOINT_POINT;
        let c = a - b;
        assert_eq!(c, &Scalar::from(0u64) * &RISTRETTO_BASEPOINT_POINT);
    }
}
