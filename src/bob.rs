use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use rug::Integer;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalSK;
use scicrypt::cryptosystems::curve_el_gamal::PrecomputedCurveElGamalPK;
use scicrypt::cryptosystems::paillier::PaillierCiphertext;
use scicrypt::cryptosystems::paillier::PaillierPK;
use scicrypt::cryptosystems::paillier::PaillierSK;
use scicrypt_traits::cryptosystems::Associable;
use scicrypt_traits::cryptosystems::DecryptionKey;
use scicrypt_traits::cryptosystems::EncryptionKey;
use scicrypt_traits::randomness::GeneralRng;
use std::sync::mpsc::{Receiver, Sender};

use crate::utils;

/// Comparison for both Alice and Bob holding plaintext values and they want to compare them.
pub fn bob_plaintext_comparison(
    tx_bob: &Sender<Vec<u8>>,
    rx_bob: &Receiver<Vec<u8>>,
    plaintext: &Integer,
    pk: &PrecomputedCurveElGamalPK,
    sk: &CurveElGamalSK,
) -> bool {
    let mut rng = GeneralRng::new(OsRng);
    let zero: RistrettoPoint = &Scalar::from(0u64) * RISTRETTO_BASEPOINT_POINT;
    let t_i = utils::cumulative_power_two(
        &(Integer::from(3) * plaintext + 1),
        std::ops::Add::add,
        0,
        &pk,
        &mut rng,
    );

    tx_bob.send(serialize(&t_i).unwrap()).unwrap(); //send encrypted t_i to Alice

    let encrypted_e_i: Vec<CurveElGamalCiphertext> = deserialize(&rx_bob.recv().unwrap()).unwrap(); //receive e_i to decrypt and check for 0.

    for c in encrypted_e_i {
        let associated_c = c.associate(pk);
        let plain = sk.decrypt(&associated_c);
        if plain == zero {
            return true;
        }
    }
    return false;
}

/// Protocol for alice holding two encrypted values, and Bob holding the key.
/// Uses bob_plaintext_comparison as a subroutine.
pub fn bob_encrypted_comparison(
    tx_bob: Sender<Vec<u8>>,
    rx_bob: Receiver<Vec<u8>>,
    pk_paillier: &PaillierPK,
    sk_paillier: &PaillierSK,
    pk_ecc: &PrecomputedCurveElGamalPK,
    sk_ecc: &CurveElGamalSK,
) -> bool {
    let mut rng = GeneralRng::new(OsRng);
    let two_l = u64::pow(2, utils::L);

    let d_enc: PaillierCiphertext = deserialize(&rx_bob.recv().unwrap()).unwrap();
    let d = sk_paillier.decrypt(&(d_enc.associate(&pk_paillier)));

    let (d_div_2_l, d_mod_2_l) = d.div_rem_floor(Integer::from(two_l));

    let d_div_2_l_enc = pk_paillier.encrypt_raw(&d_div_2_l, &mut rng);
    let d_mod_2_l_enc = pk_paillier.encrypt_raw(&d_mod_2_l, &mut rng);

    tx_bob.send(serialize(&d_div_2_l_enc).unwrap()).unwrap();
    tx_bob.send(serialize(&d_mod_2_l_enc).unwrap()).unwrap();

    let result = bob_plaintext_comparison(&tx_bob, &rx_bob, &d_mod_2_l, pk_ecc, sk_ecc);
    let lambd = match result {
        true => 1,
        false => 0,
    };

    let lambda = pk_paillier.encrypt_raw(&Integer::from(lambd), &mut rng);

    tx_bob.send(serialize(&lambda).unwrap()).unwrap();

    let final_result_enc: PaillierCiphertext = deserialize(&rx_bob.recv().unwrap()).unwrap();
    let final_result = sk_paillier.decrypt(&(final_result_enc.associate(&pk_paillier)));

    if final_result == 0 {
        tx_bob.send(serialize(&false).unwrap()).unwrap();
        return false;
    } else {
        tx_bob.send(serialize(&true).unwrap()).unwrap();
        return true;
    }
}
