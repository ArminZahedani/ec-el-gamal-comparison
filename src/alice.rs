use bincode::{deserialize, serialize};
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand_core::OsRng;
use rug::Integer;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt::cryptosystems::curve_el_gamal::PrecomputedCurveElGamalPK;
use scicrypt::cryptosystems::paillier::PaillierCiphertext;
use scicrypt::cryptosystems::paillier::PaillierPK;
use scicrypt_traits::cryptosystems::Associable;
use scicrypt_traits::cryptosystems::AssociatedCiphertext;
use scicrypt_traits::cryptosystems::EncryptionKey;
use scicrypt_traits::randomness::GeneralRng;
use std::sync::mpsc::{Receiver, Sender};

use crate::utils;

/// Comparison when Alice has a plaintext number, and bob has one, and they want to compare them.
pub fn alice_plaintext_comparison(
    tx_alice: &Sender<Vec<u8>>,
    rx_alice: &Receiver<Vec<u8>>,
    plaintext: &Integer,
    pk: &PrecomputedCurveElGamalPK,
    s: i64,
) {
    let mut rng = GeneralRng::new(OsRng);

    let v_i = utils::cumulative_power_two(
        &(Integer::from(3) * plaintext),
        std::ops::Sub::sub,
        s,
        &pk,
        &mut rng,
    ); //We use 3 * plaintext to get it work in all cases. Change s to always be 1 if non-determinism is not wanted.

    let mut encrypted_c: Vec<CurveElGamalCiphertext> = vec![];
    let received: Vec<CurveElGamalCiphertext> = deserialize(&rx_alice.recv().unwrap()).unwrap();
    for i in 0..64 as usize {
        // Add v_i's computed by alice to the t_i's from bob and add fresh randomness
        let received_rich = received[i].clone().associate(pk);
        let v_individual = v_i[i].clone().associate(pk);
        let sum = &received_rich + &v_individual;

        encrypted_c.push((&sum * &Scalar::random(rng.rng())).ciphertext);
    }
    encrypted_c.shuffle(&mut thread_rng());

    tx_alice.send(serialize(&encrypted_c).unwrap()).unwrap();
}

/// Encrypted Comparison when the two values to compare are encrypted at Alice's side, and Bob has the secret key.
/// The two values to compare are a, b and Alice does not have the key to decrypt them and has to communicate with Bob.
pub fn alice_encrypted_comparison(
    tx_alice: Sender<Vec<u8>>,
    rx_alice: Receiver<Vec<u8>>,
    a: &AssociatedCiphertext<PaillierCiphertext, PaillierPK>,
    b: &AssociatedCiphertext<PaillierCiphertext, PaillierPK>,
    pk_paillier: &PaillierPK,
    pk_ecc: &PrecomputedCurveElGamalPK,
    s: i64,
) -> bool {
    let mut rng = GeneralRng::new(OsRng);

    let two_l = Integer::from(u64::pow(2, utils::L));
    let two_l_enc = pk_paillier.encrypt(&two_l, &mut rng);

    let r = Integer::from(rand::random::<u64>());
    let r_enc = pk_paillier.encrypt(&r, &mut rng);

    let n_squared = Integer::from(pk_paillier.n.square_ref());
    let b_cpy = b.ciphertext.clone();
    let b_invert = PaillierCiphertext {
        c: b_cpy.c.invert(&n_squared).unwrap(),
    };

    let b_invert_rich = b_invert.associate(pk_paillier);

    let d = &(&two_l_enc + a) + &(&b_invert_rich + &r_enc);

    tx_alice.send(serialize(&d.ciphertext).unwrap()).unwrap();

    let d_div_2_l: PaillierCiphertext = bincode::deserialize(&rx_alice.recv().unwrap()).unwrap();
    let _d_mod_2_l: PaillierCiphertext = bincode::deserialize(&rx_alice.recv().unwrap()).unwrap();

    let d_div_2_l_rich = d_div_2_l.associate(pk_paillier);

    let (r_div_2_l, r_mod_2_l) = r.div_rem_floor(two_l); //compute floor(r/2^l) and remainder.
    let r_div_2_l_enc = pk_paillier.encrypt_raw(&r_div_2_l, &mut rng);

    let r_div_2_l_enc_inv = PaillierCiphertext {
        c: r_div_2_l_enc.c.invert(&n_squared).unwrap(),
    };

    let r_div_2_l_enc_inv_rich = r_div_2_l_enc_inv.associate(pk_paillier);

    alice_plaintext_comparison(&tx_alice, &rx_alice, &r_mod_2_l, &pk_ecc, s);

    let result_plaintext: PaillierCiphertext = deserialize(&rx_alice.recv().unwrap()).unwrap();
    let result_plaintext_invert = PaillierCiphertext {
        c: result_plaintext.c.clone().invert(&n_squared).unwrap(),
    };
    let enc_one = pk_paillier.encrypt(&Integer::from(1 as u32), &mut rng);

    let result_plaintext_invert = result_plaintext_invert.associate(pk_paillier);

    let result_plaintext = match s {
        1 => result_plaintext,
        -1 => (&enc_one + &result_plaintext_invert).ciphertext,
        _ => panic!("s should be either 0 or 1"),
    };

    let result_plaintext_invert = PaillierCiphertext {
        c: result_plaintext.c.invert(&n_squared).unwrap(),
    };

    let result_invert_rich = result_plaintext_invert.associate(pk_paillier);

    let final_result_enc = &(&d_div_2_l_rich + &r_div_2_l_enc_inv_rich) + &result_invert_rich;

    tx_alice
        .send(serialize(&final_result_enc.ciphertext).unwrap())
        .unwrap();

    let final_result: bool = deserialize(&rx_alice.recv().unwrap()).unwrap();

    final_result
}
