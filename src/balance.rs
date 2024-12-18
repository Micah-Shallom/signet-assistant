#![allow(unused)]
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 32],
}

pub struct WalletState {
    //my utxo key tuple is (txid, vout), (script_pubkey, value)
    pub utxos: HashMap<(String, u32), (Vec<u8>, f64)>,
    pub witness_programs: Vec<Vec<u8>>,
    pub public_keys: Vec<Vec<u8>>,
    pub private_keys: Vec<Vec<u8>>,
}
#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // other error variants for various cases.
    InvalidBase58Character,
    ParseError(String),
}

fn base58_decode(base58_string: &str) -> Vec<u8> {
    let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Convert Base58 string to a big integer
    let base: BigUint = BigUint::from(58u32);
    let value_decimal: BigUint =
        base58_string
            .chars()
            .rev()
            .enumerate()
            .fold(BigUint::zero(), |acc, (i, c)| {
                let pos = base58_alphabet
                    .find(c)
                    .expect("Invalid character in Base58 string");
                let value = BigUint::from(pos) * base.pow(i as u32);
                acc + value
            });

    let value_bytes = value_decimal.to_bytes_be();
    // Chop off the 32 checksum bits and return
    let (data_with_version_byte, checksum) = value_bytes.split_at(value_bytes.len() - 4);
    // Verify the checksum!
    let mut hasher = Sha256::new();
    hasher.update(data_with_version_byte);
    let hashed = hasher.finalize();
    let mut hasher2 = Sha256::new();
    hasher2.update(&hashed);
    let hash_of_hash = hasher2.finalize();
    let calculated_checksum = &hash_of_hash[0..4];
    // println!("Calculated checksum: {:?}", calculated_checksum);
    assert_eq!(calculated_checksum, checksum);
    value_bytes.to_vec()
}

fn deserialize_key(bytes: &[u8]) -> ExKey {
    ExKey {
        version: bytes[0..4].try_into().unwrap(),
        depth: [bytes[4]],
        finger_print: bytes[5..9].try_into().unwrap(),
        child_number: bytes[9..13].try_into().unwrap(),
        chaincode: bytes[13..45].try_into().expect("chaincode"),
        key: bytes[46..78].try_into().expect("failed key"),
    }
}

pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {
    let decoded_key = base58_decode(extended_private_key);
    let deserialize_key = deserialize_key(&decoded_key);

    Ok(WalletState {
        utxos: HashMap::new(),
        witness_programs: Vec::new(),
        public_keys: Vec::new(),
        private_keys: Vec::new(),
    })
}
