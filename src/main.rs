use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand_core::OsRng;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt::cryptosystems::paillier::Paillier;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::SecureRng;
use scicrypt_traits::Enrichable;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time::Duration};

const L: usize = 16;

fn alice(tx_alice: Sender<Vec<u8>>, rx_alice: Receiver<Vec<u8>>, plaintext: u32) -> u32 {
    let one: RistrettoPoint = &Scalar::from(1u64) * RISTRETTO_BASEPOINT_POINT;
    let mut rng = SecureRng::new(OsRng);
    let received = rx_alice.recv().unwrap();
    let pk = bincode::deserialize(&received).unwrap();

    //Improvement from paper
    let delta: bool = rand::random();
    let s: i32 = match delta {
        false => 1,
        true => -1,
    };

    let v_i = cumulative_power_two(plaintext, std::ops::Sub::sub, s, &pk, &mut rng);

    let mut encrypted_c: Vec<CurveElGamalCiphertext> = vec![];
    let received: Vec<CurveElGamalCiphertext> = deserialize(&rx_alice.recv().unwrap()).unwrap();
    for i in 0..L {
        // Add v_i's computed by alice to the t_i's from bob and add fresh randomness
        encrypted_c.push(&(&received[i] + &v_i[i]) * &Scalar::random(rng.rng()));
    }
    encrypted_c.shuffle(&mut thread_rng());

    tx_alice.send(serialize(&encrypted_c).unwrap()).unwrap();

    let lambda_prime: CurveElGamalCiphertext = deserialize(&rx_alice.recv().unwrap()).unwrap();
    let lambda = match s {
        1 => lambda_prime,
        -1 => &CurveElGamal::encrypt(&one, &pk, &mut rng) + &-&lambda_prime,
        _ => panic!("s should be either 1 or -1, but never anything else!"),
    };

    //tx_alice.send(serialize(&lambda).unwrap()).unwrap();

    thread::sleep(Duration::from_millis(100));
    0
}

fn bob(tx_bob: Sender<Vec<u8>>, rx_bob: Receiver<Vec<u8>>, plaintext: u32, i: u32, j: u32) -> u32 {
    let zero: RistrettoPoint = &Scalar::from(0u64) * RISTRETTO_BASEPOINT_POINT;
    let one: RistrettoPoint = &Scalar::from(1u64) * RISTRETTO_BASEPOINT_POINT;
    let mut rng = SecureRng::new(OsRng);
    let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);

    tx_bob.send(serialize(&pk).unwrap()).unwrap();

    //Improvement from paper
    let t_i = cumulative_power_two(plaintext, std::ops::Add::add, 0, &pk, &mut rng);
    tx_bob.send(serialize(&t_i).unwrap()).unwrap();

    let encrypted_c: Vec<CurveElGamalCiphertext> = deserialize(&rx_bob.recv().unwrap()).unwrap();

    let mut sent: bool = false;
    for c in encrypted_c {
        let plain = CurveElGamal::decrypt(&c.enrich(&pk), &sk);
        if plain == zero {
            let delta = &CurveElGamal::encrypt(&one, &pk, &mut rng);
            tx_bob.send(serialize(&delta).unwrap()).unwrap();
            sent = true;
            break;
        }
    }
    if !sent {
        let delta = &CurveElGamal::encrypt(&zero, &pk, &mut rng);
        tx_bob.send(serialize(&delta).unwrap()).unwrap();
    }
    }
    0
}
//TODO: Look into the use of closure here again.
fn cumulative_power_two<F>(
    plain_number: u32,
    f: F,
    s: i32,
    pk: &RistrettoPoint,
    rng: &mut SecureRng<rand_core::OsRng>,
) -> Vec<CurveElGamalCiphertext>
where
    F: Fn(i32, i32) -> i32,
{
    let number_bin = format!("{:016b}", plain_number);
    let mut messages: Vec<CurveElGamalCiphertext> = vec![];

    for (i, bit) in number_bin.chars().rev().enumerate() {
        let plaintext: i32 = bit.to_digit(2).unwrap() as i32;
        let mut offset: u32 = 0;
        for j in i + 1..16 {
            //todo, use .to_digit here as well
            let plaintext2: u32 = match number_bin.chars().rev().nth(j).unwrap() {
            '0' => 0,
            '1' => 1,
            _ => panic!("Error: Bit in binary representation is not 0 or 1"),
        };
            offset += plaintext2 * u32::pow(2, j as u32);
        }
        
        let result = f(f(s, plaintext), offset as i32);
        let plaintext_encoded: RistrettoPoint;
        if result < 0 {
            plaintext_encoded = -&Scalar::from(result.abs() as u32) * &RISTRETTO_BASEPOINT_POINT;
        } else {
            plaintext_encoded = &Scalar::from(result as u32) * &RISTRETTO_BASEPOINT_POINT;
        }
        messages.push(CurveElGamal::encrypt(&plaintext_encoded, &pk, rng));
    }
    messages.reverse();
    messages
}

fn main() {
    //Alice is the main thread, Bob is the thread we create.
    let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let i = 25;
    let j = 5;
    thread::spawn(move || {
        bob(tx_bob, rx_bob, j, i, j);
    });

    alice(tx_alice, rx_alice, i);
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
