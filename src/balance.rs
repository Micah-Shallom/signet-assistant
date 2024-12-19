#![allow(unused)]
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use hex_literal::hex;
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
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

fn get_child_key_at_path(key: ExKey, derivation_path: &str) -> ExKey {
    let mut derived_key = key.clone();
    // skip 'm'
    for component in derivation_path.split('/').skip(1) {
        let hardened = component.ends_with("'") || component.ends_with("h");
        let index_str = component.trim_end_matches("'").trim_end_matches("h");
        let child_num = index_str.parse::<u32>().expect("Invalid child number");

        // Adjust child_num for hardened keys
        let child_num = if hardened {
            child_num + 2147483648
        } else {
            child_num
        };
        derived_key = derive_priv_child(derived_key, child_num);
    }
    derived_key
}

fn derive_priv_child(key: ExKey, child_num: u32) -> ExKey {
    let curve_order = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let big_n = BigUint::from_bytes_be(&curve_order);

    let mut data_vec = Vec::with_capacity(37);

    let mut hmac =
        Hmac::<Sha512>::new_from_slice(&key.chaincode).expect("HMAC initialization failed");

    if child_num >= 0x80000000 {
        // Hardened derivation
        // Data = 0x00 || parent private key || ser32(i)
        data_vec.extend_from_slice(&[0]);
        data_vec.extend_from_slice(&key.key);
    } else {
        // Normal derivation
        // Data = parent public key || ser32(i)
        let parent_pubkey = derive_public_key_from_private(&key.key);

        data_vec.extend_from_slice(&parent_pubkey);
    }

    data_vec.extend_from_slice(&child_num.to_be_bytes());

    hmac.update(&data_vec);
    let result = hmac.finalize().into_bytes();

    //split the left and right halves
    let il = &result[0..32]; //used as child key
    let ir = &result[32..]; //used as child chain code

    let mut child_key = [0u8; 32];
    
    let sum = (BigUint::from_bytes_be(&key.key) + BigUint::from_bytes_be(&il)) % &big_n;
    let mut sum_bytes = sum.to_bytes_be();
    while sum_bytes.len() < 32 {
        sum_bytes.insert(0, 0);
    }
    child_key.copy_from_slice(&sum_bytes[..32]);

    let new_depth = [key.depth[0] + 1];

    //calculate parent fingerprint
    let parent_pubkey = derive_public_key_from_private(&key.key);

    let mut hasher = Sha256::new();
    hasher.update(&parent_pubkey);
    let sha256_result = hasher.finalize();

    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_result);
    let ripemd_result = ripemd160.finalize();

    let mut finger_print = [0u8; 4];
    finger_print.copy_from_slice(&ripemd_result[0..4]);

    ExKey {
        version: key.version,
        depth: new_depth,
        finger_print,
        child_number: child_num.to_be_bytes(),
        chaincode: ir.to_vec().try_into().unwrap(),
        key: child_key,
    }
}

fn derive_public_key_from_private(key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&key).expect("Expected 32 bytes");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    public_key.serialize().to_vec()
}

fn get_keys_at_child_key_path(child_key: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut keys = Vec::with_capacity(num_keys as usize);

    for i in 0..num_keys {
        let current_key = derive_priv_child(child_key.clone(), i);
        keys.push(current_key);
    }

    return keys;
}

// Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key
fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    if pubkey.len() != 33 || (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
        panic!("Invalid compressed public key");
    }

    let mut hasher = Sha256::new();
    hasher.update(&pubkey);
    let sha256_result = hasher.finalize();

    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_result);
    let ripemd_result = ripemd160.finalize();

    let mut witness_program = Vec::with_capacity(22);
    witness_program.push(0x00); // OP_0 (witness version 0)
    witness_program.push(0x14); // Push 20 bytes
    witness_program.extend_from_slice(&ripemd_result);

    witness_program
}



pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {
    let decoded_key = base58_decode(extended_private_key);
    let deserialize_key = deserialize_key(&decoded_key);

    //derive the key by using the path in descriptor
    let derivation_path: &str = "m/84h/1h/0h/0";
    let child_key = get_child_key_at_path(deserialize_key, derivation_path);

    // Get the child key at the derivation path
    // Compute 2000 private keys from the child key path
    let child_keys = get_keys_at_child_key_path(child_key, 2000);

    // For each private key, collect compressed public keys and witness programs
    let mut private_keys = vec![];
    let mut public_keys = vec![];
    let mut witness_programs = vec![];
    let mut cprivate_keys = HashMap::<String, bool>::new();
    let mut cpublic_keys = HashMap::<String, bool>::new();
    let mut cwitness_programs = HashMap::<String, bool>::new();

    for cpriv_key in child_keys.clone() {
        let priv_key = cpriv_key.key;
        cprivate_keys.insert(hex::encode(priv_key.to_vec()), true);

        let pub_key = derive_public_key_from_private(&priv_key);
        cpublic_keys.insert(hex::encode(pub_key.clone()), true);

        let witness_program = get_p2wpkh_program(&pub_key);
        cwitness_programs.insert(hex::encode(witness_program.clone()), true);

        private_keys.push(priv_key.to_vec());
        public_keys.push(pub_key.to_vec());
        witness_programs.push(witness_program.to_vec());
    }

    Ok(WalletState {
        utxos: HashMap::new(),
        witness_programs: Vec::new(),
        public_keys: Vec::new(),
        private_keys: Vec::new(),
    })
}
