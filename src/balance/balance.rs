#![allow(unused)]
use hex_literal::hex;
use hmac::{Hmac, Mac};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::{path::PathBuf, process::Command};

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

impl WalletState {
    // Given a WalletState find the balance is satoshis
    pub fn balance(&self) -> f64 {
        self.utxos.values().map(|(_, value)| value).sum()
    }
}

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // other error variants for various cases.
    InvalidBase58Character,
    ParseError(String),
}

#[derive(Debug)]
struct ScanInputs {
    cpublic_keys: HashMap<String, bool>,
    cwitness_programs: HashMap<String, bool>,
    outgoing_txs: Vec<Vec<u8>>,
    spending_txs: Vec<Vec<u8>>,
    utxos: HashMap<(String, u32), (Vec<u8>, f64)>,
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

pub fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let mut args = vec!["-signet"];
    args.extend(cmd.split(' '));

    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;

    if result.status.success() {
        return Ok(result.stdout);
    } else {
        return Ok(result.stderr);
    }
}

fn fetch_block(block_number: u32) -> Result<Value, BalanceError> {
    let block_hash_cmd = format!("-signet getblockhash {}", block_number);
    let block_hash = match bcli(&block_hash_cmd) {
        Ok(hash) => String::from_utf8_lossy(&hash).trim().to_string(),
        Err(e) => return Err(e),
    };

    let block_cmd = format!("-signet getblock {} 2", block_hash);
    let block_data = match bcli(&block_cmd) {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    //return it as serde_json::Value
    serde_json::from_slice(&block_data).map_err(|e| BalanceError::ParseError(e.to_string()))
}

fn parse_block_transactions(
    block_json: &Value,
    scan_inputs: &mut ScanInputs,
) -> Result<(), BalanceError> {
    let transactions = block_json["tx"]
        .as_array()
        .ok_or_else(|| BalanceError::ParseError("No transactions found in block".to_string()))?;

    for tx in transactions {
        parse_transaction(tx, scan_inputs)?;
    }

    Ok(())
}

fn parse_transaction(tx: &Value, scan_inputs: &mut ScanInputs) -> Result<(), BalanceError> {
    let txid = tx["txid"]
        .as_str()
        .ok_or_else(|| BalanceError::ParseError("Missing txid".to_string()))?
        .to_string();

    let inputs = tx["vin"]
        .as_array()
        .ok_or_else(|| BalanceError::ParseError("Missing vin".to_string()))?;

    let outputs = tx["vout"]
        .as_array()
        .ok_or_else(|| BalanceError::ParseError("Missing vout".to_string()))?;

    for input in inputs {
        if let Some(witness_array) = input["txinwitness"].as_array() {
            if let Some(pubkey) = witness_array.last() {
                if let Some(pubkey_str) = pubkey.as_str() {
                    if scan_inputs.cpublic_keys.contains_key(pubkey_str) {
                        scan_inputs.spending_txs.push(hex::decode(&txid).unwrap());
                    }
                }
            }

            if let (Some(prev_txid), Some(prev_vout)) =
                (input["txid"].as_str(), input["vout"].as_u64())
            {
                let outpoint_key = (prev_txid.to_string(), prev_vout as u32);
                scan_inputs.utxos.remove(&outpoint_key);
            }
        }
    }

    for (vout, output) in outputs.iter().enumerate() {
        if let Some(script_pub_key) = output["scriptPubKey"]["hex"].as_str() {
            if scan_inputs.cwitness_programs.contains_key(script_pub_key) {
                // This output is paying to our address
                let value = (output["value"].as_f64()); // Convert BTC to satoshis
                let outpoint_key = (txid.clone(), vout as u32);
                scan_inputs.utxos.insert(
                    outpoint_key,
                    (hex::decode(script_pub_key).unwrap(), value.unwrap()),
                );
            }
        }
    }

    Ok(())
}

fn scan_blockchain(scan_inputs: &mut ScanInputs) -> Result<(), BalanceError> {
    let mut signet_block_count = bcli("-signet getblockcount")?;

    let signet_block_count = String::from_utf8_lossy(&signet_block_count)
        .trim()
        .parse::<u32>()
        .map_err(|_| BalanceError::ParseError("Invalid block count".to_string()))?;

    let end_index = if signet_block_count > 300 {
        300
    } else {
        signet_block_count
    };

    for height in 0..=end_index {
        let block_data = fetch_block(height)?;
        parse_block_transactions(&block_data, scan_inputs)?;
    }

    Ok(())
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

    let mut outgoing_txs: Vec<Vec<u8>> = vec![];
    let mut spending_txs: Vec<Vec<u8>> = vec![];
    let mut utxos: HashMap<(String, u32), (Vec<u8>, f64)> = HashMap::new();

    let mut scan_inputs = ScanInputs {
        cpublic_keys: cpublic_keys.clone(),
        cwitness_programs: cwitness_programs.clone(),
        outgoing_txs: outgoing_txs,
        spending_txs: spending_txs,
        utxos: utxos.clone(),
    };

    // Scan blocks 0 to 300 for transactions
    scan_blockchain(&mut scan_inputs)?;

    Ok(WalletState {
        utxos: scan_inputs.utxos.clone(),
        public_keys,
        private_keys,
        witness_programs,
    })
}
