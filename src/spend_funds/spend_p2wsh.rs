use crate::balance::balance::WalletState;
use crate::spend_funds::spend_p2wpkh::{
    create_multisig_script, input_from_utxo, output_from_options, SpendError, Outpoint, Utxo, get_commitment_hash, get_txid, assemble_transaction, get_p2wsh_witness
};

pub fn spend_p2wsh(wallet_state: &WalletState, txid: [u8; 32]) -> Result<Vec<Vec<u8>>, SpendError> {
    // COIN_VALUE = 1000000
    // FEE = 1000
    // AMT = 0
    // Create the input from the utxo
    const FEE: u64 = 1000;
    const AMT: u64 = 1000000;

    let vout_index = 0; //index of the ouput AMT was sent

    // Reverse the txid hash so it's little-endian
    let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();

    let transaction_input = input_from_utxo(&reversed_txid, vout_index);

    let pubkey1 = wallet_state.public_keys[0].clone();
    let pubkey2 = wallet_state.public_keys[1].clone();

    let multisig_redeem_script = create_multisig_script(vec![pubkey1, pubkey2]);
    // let multisig_witness_program = get_p2wsh_program(&multisig_redeem_script, Some(0));;

    // Compute destination output script and output
    // Create the OP_RETURN output with your name (or nym) in ASCII
    let name = "Shallom Micah Bawa"; // Replace with your name or nym
    let mut op_return_script = vec![
        0x6a,             // OP_RETURN
        name.len() as u8, // Pushdata length
    ];
    op_return_script.extend_from_slice(name.as_bytes());
    let op_return_output = output_from_options(&op_return_script, 0);

    // Compute change output script and output
    let change_amount = AMT - FEE;
    let change_output = output_from_options(&wallet_state.witness_programs[0], change_amount);

    // Get the message to sign
    // 1.create an outpoint
    let outpoint = Outpoint {
        txid: reversed_txid.try_into().unwrap(),
        index: vout_index,
    };
    // 2.define the outputs for the transaction
    let transaction_outputs = vec![
        //output from p2wsh; input to the p2wpkh
        Utxo {
            script_pubkey: op_return_script.clone(),
            amount: 0,
        },
        //change into the sender
        Utxo {
            script_pubkey: wallet_state.witness_programs[0].clone(),
            amount: change_amount,
        },
    ];

    // Sign!
    let commitment_hash = get_commitment_hash(
        outpoint,
        &multisig_redeem_script, //scriptcode for p2wsh is the redeem script,
        AMT,
        transaction_outputs,
    );

    // Fetch the private keys needed to sign the input
    let privkey1: [u8; 32] = wallet_state.private_keys[0]
        .clone()
        .try_into()
        .expect("private key length is not 32 bytes");
    let privkey2: [u8; 32] = wallet_state.private_keys[1]
        .clone()
        .try_into()
        .expect("private key length is not 32 bytes");

    // Sign the transaction input
    let witness = get_p2wsh_witness(
        vec![&privkey1, &privkey2],
        commitment_hash,
        &multisig_redeem_script,
    );

    // Assemble
    let transaction_inputs = vec![transaction_input.clone()];
    let transaction_outputs = vec![op_return_output.clone(), change_output.clone()];
    let transaction_witnesses = vec![witness.clone()];

    let transaction = assemble_transaction(
        transaction_inputs.clone(),
        transaction_outputs.clone(),
        transaction_witnesses,
    );

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    // return txid final-tx
    let txid2 = get_txid(transaction_inputs, transaction_outputs);

    // println!("Transaction ID (hex): {}", hex::encode(&txid));

    // Return the TXID and the hex-encoded transaction
    Ok(vec![txid2.to_vec(), transaction])
}
