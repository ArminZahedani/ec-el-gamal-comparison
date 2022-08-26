use ec_el_gamal_comparison;

#[cfg(test)]
mod tests {
    use crate::ec_el_gamal_comparison::{alice, bob};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use rand_core::OsRng;
    use rug::Integer;
    use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
    use scicrypt::cryptosystems::paillier::Paillier;
    use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
    use scicrypt_traits::cryptosystems::EncryptionKey;
    use scicrypt_traits::randomness::GeneralRng;
    use scicrypt_traits::security::BitsOfSecurity;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::thread;

    #[test]
    fn test_ciphertext_comparison_random() {
        let mut r = StdRng::seed_from_u64(42);
        for _i in 0..10 {
            let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
            let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let mut rng = GeneralRng::new(OsRng);

            let el_gamal = CurveElGamal::setup(&Default::default());
            let (pk_ecc, sk_ecc) = el_gamal.generate_keys(&mut rng);
            let pk_ecc_clone = pk_ecc.clone();

            let paillier = Paillier::setup(&BitsOfSecurity::ToyParameters);
            let (pk_paillier, sk_paillier) = paillier.generate_keys(&mut rng);
            let pk_paillier_clone = pk_paillier.clone();

            let a_org: u32 = r.gen();
            let b_org: u32 = r.gen();

            let a = pk_paillier.encrypt(&Integer::from(a_org), &mut rng);
            let b = pk_paillier.encrypt(&Integer::from(b_org), &mut rng);
            thread::spawn(move || {
                bob::bob_encrypted_comparison(
                    tx_bob,
                    rx_bob,
                    &pk_paillier_clone,
                    &sk_paillier,
                    &pk_ecc_clone,
                    &sk_ecc,
                );
            });

            let delta: bool = rand::random();
            let s: i64 = match delta {
                false => 1,
                true => -1,
            };

            let result = alice::alice_encrypted_comparison(
                tx_alice,
                rx_alice,
                a,
                b,
                &pk_paillier,
                &pk_ecc,
                s,
            );
            assert_eq!(result, a_org > b_org);
        }
    }

    #[test]
    fn test_plaintext_comparison_random() {
        let mut r = StdRng::seed_from_u64(42);
        for _i in 0..10 {
            let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
            let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let mut rng = GeneralRng::new(OsRng);

            let el_gamal = CurveElGamal::setup(&Default::default());
            let (pk_ecc, sk_ecc) = el_gamal.generate_keys(&mut rng);
            let pk_ecc_clone = pk_ecc.clone();

            let a_org: u32 = r.gen();
            let b_org: u32 = r.gen();

            let delta: bool = rand::random();

            let s: i64 = match delta {
                false => 1,
                true => 1, //THIS SHOULD BE -1 in a real implementation.
            }; //make s deterministic, so that the test succeeds

            thread::spawn(move || {
                alice::alice_plaintext_comparison(
                    &tx_alice,
                    &rx_alice,
                    Integer::from(a_org),
                    &pk_ecc,
                    s,
                );
            });

            let result = bob::bob_plaintext_comparison(
                &tx_bob,
                &rx_bob,
                Integer::from(b_org),
                &pk_ecc_clone,
                &sk_ecc,
            );
            assert_eq!(result, a_org > b_org);
        }
    }
    #[test]
    fn test_plaintext_comparison_inverted_random() {
        let mut r = StdRng::seed_from_u64(42);
        for _i in 0..10 {
            let (tx_alice, rx_bob): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
            let (tx_bob, rx_alice): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();

            let mut rng = GeneralRng::new(OsRng);

            let el_gamal = CurveElGamal::setup(&Default::default());
            let (pk_ecc, sk_ecc) = el_gamal.generate_keys(&mut rng);
            let pk_ecc_clone = pk_ecc.clone();

            let a_org: u32 = r.gen();
            let b_org: u32 = r.gen();

            let delta: bool = rand::random();

            let s: i64 = match delta {
                false => -1, //THIS SHOULD BE 1 in a real implementation.
                true => -1,
            }; //make s deterministic, so that the test succeeds

            thread::spawn(move || {
                alice::alice_plaintext_comparison(
                    &tx_alice,
                    &rx_alice,
                    Integer::from(a_org),
                    &pk_ecc,
                    s,
                );
            });

            let result = bob::bob_plaintext_comparison(
                &tx_bob,
                &rx_bob,
                Integer::from(b_org),
                &pk_ecc_clone,
                &sk_ecc,
            );
            assert_eq!(!result, a_org > b_org); //negate the result as s is always -1.
        }
    }
}
