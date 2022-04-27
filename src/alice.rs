use bincode::{deserialize, serialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand_core::OsRng;
use rug::Integer;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt::cryptosystems::paillier::Paillier;
use scicrypt::cryptosystems::paillier::PaillierCiphertext;
use scicrypt::cryptosystems::paillier::PaillierPublicKey;
use scicrypt::cryptosystems::paillier::RichPaillierCiphertext;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::GeneralRng;
use scicrypt_traits::Enrichable;
use std::sync::mpsc::{Receiver, Sender};

use crate::utils;

///Comparison when Alice has a plaintext number, and bob has one, and they want to compare them.
pub fn alice_plaintext_comparison(
    tx_alice: &Sender<Vec<u8>>,
    rx_alice: &Receiver<Vec<u8>>,
    plaintext: Integer,
    pk: RistrettoPoint,
) -> bool {
    let mut rng = GeneralRng::new(OsRng);
    let delta: bool = rand::random();

    //Not used atm.
    let _s: i32 = match delta {
        false => 1,
        true => -1,
    };

    let v_i = utils::cumulative_power_two(plaintext, std::ops::Sub::sub, 1, &pk, &mut rng); //the 1 should be s, if non-determinism is wanted.

    let mut encrypted_c: Vec<CurveElGamalCiphertext> = vec![];
    let received: Vec<CurveElGamalCiphertext> = deserialize(&rx_alice.recv().unwrap()).unwrap();
    for i in 0..utils::L as usize {
        // Add v_i's computed by alice to the t_i's from bob and add fresh randomness
        encrypted_c.push(&(&received[i] + &v_i[i]) * &Scalar::random(rng.rng()));
    }
    encrypted_c.shuffle(&mut thread_rng());

    tx_alice.send(serialize(&encrypted_c).unwrap()).unwrap();

    deserialize(&rx_alice.recv().unwrap()).unwrap() //receive the final result again.
}

/// Encrypted Comparison when the two values to compare are encrypted at Alice's side, and Bob has the secret key.
/// The two values to compare are a, b and Alice does not have the key to decrypt them and has to communicate with Bob.
pub fn alice_encrypted_comparison(
    tx_alice: Sender<Vec<u8>>,
    rx_alice: Receiver<Vec<u8>>,
    a: RichPaillierCiphertext,
    b: RichPaillierCiphertext,
    pk_paillier: &PaillierPublicKey,
    pk_ecc: RistrettoPoint,
) -> bool {
    let mut rng = GeneralRng::new(OsRng);

    let two_l = Integer::from(u64::pow(2, utils::L));
    let two_l_enc = Paillier::encrypt(&two_l, &pk_paillier, &mut rng).enrich(&pk_paillier);

    let r = Integer::from(rand::random::<u64>());
    let r_enc = Paillier::encrypt(&r, &pk_paillier, &mut rng).enrich(&pk_paillier);

    let n_squared = Integer::from(pk_paillier.n.square_ref());
    let b_invert = PaillierCiphertext {
        c: b.ciphertext.c.invert(&n_squared).unwrap(),
    };

    let b_invert_rich = b_invert.enrich(&pk_paillier);

    let d = &(&(&two_l_enc + &a) + &b_invert_rich) + &r_enc;

    tx_alice.send(serialize(&d.ciphertext).unwrap()).unwrap();

    let d_div_2_l: PaillierCiphertext = bincode::deserialize(&rx_alice.recv().unwrap()).unwrap();
    let _d_mod_2_l: PaillierCiphertext = bincode::deserialize(&rx_alice.recv().unwrap()).unwrap();

    let d_div_2_l_rich = d_div_2_l.enrich(&pk_paillier);

    let (r_div_2_l, r_mod_2_l) = r.div_rem_floor(two_l); //compute floor(r/2^l) and remainder.
    let r_div_2_l_enc = Paillier::encrypt(&r_div_2_l, &pk_paillier, &mut rng);

    let r_div_2_l_enc_inv = PaillierCiphertext {
        c: r_div_2_l_enc.c.invert(&n_squared).unwrap(),
    };

    let r_div_2_l_enc_inv_rich = r_div_2_l_enc_inv.enrich(&pk_paillier);

    alice_plaintext_comparison(&tx_alice, &rx_alice, r_mod_2_l, pk_ecc);

    let result_plaintext: PaillierCiphertext = deserialize(&rx_alice.recv().unwrap()).unwrap();

    let result_plaintext_invert = PaillierCiphertext {
        c: result_plaintext.c.invert(&n_squared).unwrap(),
    };

    let result_invert_rich = result_plaintext_invert.enrich(&pk_paillier);

    let final_result_enc = &(&d_div_2_l_rich + &r_div_2_l_enc_inv_rich) + &result_invert_rich;

    tx_alice
        .send(serialize(&final_result_enc.ciphertext).unwrap())
        .unwrap();

    let final_result: bool = deserialize(&rx_alice.recv().unwrap()).unwrap();
    
    final_result
}
