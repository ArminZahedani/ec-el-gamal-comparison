use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rug::Integer;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamal;
use scicrypt::cryptosystems::curve_el_gamal::CurveElGamalCiphertext;
use scicrypt_traits::cryptosystems::AsymmetricCryptosystem;
use scicrypt_traits::randomness::GeneralRng;

pub const L: u32 = 32;

/// Computes the adding sum x_i * (2^i) factors from the paper
/// f is a function, either + or - for the two cases
pub fn cumulative_power_two<F>(
    plain_number: Integer,
    f: F,
    s: i64,
    pk: &RistrettoPoint,
    rng: &mut GeneralRng<rand_core::OsRng>,
) -> Vec<CurveElGamalCiphertext>
where
    F: Fn(i64, i64) -> i64,
{
    let number_bin = format!("{:032b}", plain_number);
    let mut messages: Vec<CurveElGamalCiphertext> = vec![];
    for (i, bit) in number_bin.chars().rev().enumerate() {
        let plaintext: i64 = bit.to_digit(2).unwrap() as i64;
        let mut offset: u64 = 0;
        for j in i + 1..L as usize {
            //todo, use .to_digit here as well
            let plaintext2: u64 = number_bin
                .chars()
                .rev()
                .nth(j)
                .unwrap()
                .to_digit(2)
                .unwrap()
                .into();
            offset += plaintext2 * u64::pow(2, j as u32);
        }
        let result = f(f(s, plaintext), offset as i64);
        let plaintext_encoded: RistrettoPoint;
        if result < 0 {
            plaintext_encoded = -&Scalar::from(result.abs() as u64) * &RISTRETTO_BASEPOINT_POINT;
        } else {
            plaintext_encoded = &Scalar::from(result as u64) * &RISTRETTO_BASEPOINT_POINT;
        }
        messages.push(CurveElGamal::encrypt(&plaintext_encoded, &pk, rng));
    }
    messages.reverse();
    messages
}
