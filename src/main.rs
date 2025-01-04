mod balance;
mod spend_funds;
mod block_selection;
use crate::balance::balance::WalletState;
use std::env;

use balance::balance::recover_wallet_state;
use dotenv::dotenv;
use spend_funds::spend_p2wpkh::spend_p2wpkh;
use spend_funds::spend_p2wsh::spend_p2wsh;

use block_selection::parser;
use block_selection::degraph;

fn main() {
    let cookie_filepath = "~/.bitcoin/signet/.cookie";
    dotenv().ok();

    let extended_private_key =
        env::var("EXTENDED_PRIVATE_KEY").expect("extended private key url must be set");
    let wallet_name = env::var("WALLET_NAME").expect("extended private key url must be set");

    let wallet_state: WalletState =
        recover_wallet_state(extended_private_key.as_str(), cookie_filepath).unwrap();
    let balance = wallet_state.balance();

    println!("{} {:.8}", wallet_name, balance);


    // Spend from P2WPKH and create a P2WSH multisig output
    let (txid1, _tx1) = spend_p2wpkh(&wallet_state).unwrap();

    //spend from the p2wsh multisig output
    match spend_p2wsh(&wallet_state, txid1) {
        Ok(transaction_data) => {
            let _txid2 = hex::encode(&transaction_data[0]); // TXID of the second transaction
            let tx2 = hex::encode(&transaction_data[1]); // Serialized transaction

            // println!("Second transaction (P2WSH -> OP_RETURN + Change) created successfully.");
            // println!("Transaction 2 ID: {}", txid2);
            println!("{}", tx2);
        }
        Err(e) => {
            println!("Failed to create the second transaction: {:?}", e);
        }
    }


    //block selection 
    let file_path: &str =
        "/home/mshallom/Documents/WorkSpaces/Projects/Block-Construction/mempool.csv";
    let output_path =
        "/home/mshallom/Documents/WorkSpaces/Projects/Block-Construction/block.txt";
    let max_block_weight = 4_000_000;

    let mempool_transaction = parser::parse_mempool(file_path).unwrap();
    let transaction_order = degraph::build_and_sort(&mempool_transaction);

}
