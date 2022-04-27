use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_core::OsRng;
use rug::Integer;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt::cryptosystems::paillier::Paillier;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::security::BitsOfSecurity;
use scicrypt_traits::Enrichable;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time::Duration};

mod alice;
mod bob;
mod utils;

fn main() {
    //algo computes i >? j.
    let mut rng = GeneralRng::new(OsRng);
    let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

    let i = 150;
    let j = 170;

    let (pk_ecc, sk_ecc) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
    let (pk_paillier, sk_paillier) =
        Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);
    let pk_paillier_clone = pk_paillier.clone();

    let a = Paillier::encrypt(&Integer::from(i), &pk_paillier, &mut rng).enrich(&pk_paillier);
    let b = Paillier::encrypt(&Integer::from(j), &pk_paillier, &mut rng).enrich(&pk_paillier);

    thread::spawn(move || {
        bob::bob_encrypted_comparison(
            tx_bob,
            rx_bob,
            pk_paillier_clone,
            sk_paillier,
            pk_ecc,
            sk_ecc,
        );
    });

    let result = alice::alice_encrypted_comparison(tx_alice, rx_alice, a, b, &pk_paillier, pk_ecc);
    assert_eq!(result, i > j);

    let mut r = StdRng::seed_from_u64(42);
    for _i in 0..100 {
        let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

        let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

        let mut rng = GeneralRng::new(OsRng);
        let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
        let a: u32 = r.gen();
        let b: u32 = r.gen();

        thread::spawn(move || {
            bob::bob_plaintext_comparison(&tx_bob, &rx_bob, Integer::from(a as u32), pk, sk);
        });

        let result =
            alice::alice_plaintext_comparison(&tx_alice, &rx_alice, Integer::from(b as u32), pk);
        assert_eq!(result, a < b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_plaintext_comparison() {
        let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

        let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

        let mut rng = GeneralRng::new(OsRng);
        let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
        let a: u64 = 3651085478;
        let b: u64 = 3421349512;

        thread::spawn(move || {
            bob::bob_plaintext_comparison(&tx_bob, &rx_bob, Integer::from(a as u32), pk, sk);
            //bob gets i, alice gets j.
        });

        let result =
            alice::alice_plaintext_comparison(&tx_alice, &rx_alice, Integer::from(b as u32), pk);
        assert_eq!(result, a < b);
    }
    #[test]
    fn test_plaintext_comparison_random() {
        let mut r = StdRng::seed_from_u64(42);
        for _i in 0..1000 {
            let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let mut rng = GeneralRng::new(OsRng);
            let (pk, sk) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
            let a: u32 = r.gen();
            let b: u32 = r.gen();

            thread::spawn(move || {
                bob::bob_plaintext_comparison(&tx_bob, &rx_bob, Integer::from(a as u32), pk, sk);
            });

            let result = alice::alice_plaintext_comparison(
                &tx_alice,
                &rx_alice,
                Integer::from(b as u32),
                pk,
            );
            assert_eq!(result, a < b);
        }
    }

    #[test]
    fn test_ciphertext_comparison() {
        let mut r = StdRng::seed_from_u64(42);
        for _i in 0..1000 {
            let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let mut rng = GeneralRng::new(OsRng);
            let (pk_ecc, sk_ecc) = CurveElGamal::generate_keys(&Default::default(), &mut rng);
            let a_org: u32 = r.gen();
            let b_org: u32 = r.gen();

            let (pk_paillier, sk_paillier) =
                Paillier::generate_keys(&BitsOfSecurity::Other { pk_bits: 160 }, &mut rng);
            let pk_paillier_clone = pk_paillier.clone();

            let a = Paillier::encrypt(&Integer::from(a_org), &pk_paillier, &mut rng)
                .enrich(&pk_paillier);
            let b = Paillier::encrypt(&Integer::from(b_org), &pk_paillier, &mut rng)
                .enrich(&pk_paillier);
            thread::spawn(move || {
                bob::bob_encrypted_comparison(
                    tx_bob,
                    rx_bob,
                    pk_paillier_clone,
                    sk_paillier,
                    pk_ecc,
                    sk_ecc,
                );
            });

            let result =
                alice::alice_encrypted_comparison(tx_alice, rx_alice, a, b, &pk_paillier, pk_ecc);
            assert_eq!(result, a_org > b_org);
        }
    }
}
