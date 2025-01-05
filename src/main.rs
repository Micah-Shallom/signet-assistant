mod balance;
mod spend_funds;
mod block_selection;
use std::env;

use balance::balance::recover_wallet_state;
use dotenv::dotenv;
use spend_funds::spend_p2wpkh::spend_p2wpkh;
use spend_funds::spend_p2wsh::spend_p2wsh;

use block_selection::blockparser::parse_mempool;
use block_selection::degraph::build_and_sort;
use block_selection::test;
use block_selection::selection::select_transactions;
use block_selection::write::write_block_to_file;

use clap::{Parser, Subcommand, command};

#[derive(Parser)]
#[command(name = "Signet Assistant", about = "A Bitcoin Signet utility for wallet management and block construction")]
struct CLI {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    //waller related operations
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    //build optimized block from a mempool file
    Block {
        mempool_file:String,
        output_file: String,
    }
}

#[derive(Subcommand)]
enum WalletAction{
    Recover,
    SpendMultisig,
    SpendOpreturn{
        txid: String,
    }
}

fn main() {
    //load environment variables
    dotenv().ok();
    let extended_private_key = env::var("EXTENDED_PRIVATE_KEY").expect("EXTENDED_PRIVATE_KEY must be set");
    let wallet_name = env::var("WALLET_NAME").expect("WALLET_NAME must be set");
    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    //parse cli arguments
    let cli = CLI::parse();
    match cli.command {
        Commands::Wallet { action } => {
            // Recover wallet state for all wallet actions
            let wallet_state = recover_wallet_state(&extended_private_key, cookie_filepath)
                .expect("Failed to recover wallet state");

            match action {
                WalletAction::Recover => {
                    let balance = wallet_state.balance();
                    println!("Wallet: {}\nBalance: {:.8} BTC", wallet_name, balance);
                    println!("UTXOs: {}", wallet_state.utxos.len());
                    for ((txid, vout), (script, amount)) in &wallet_state.utxos {
                        println!("- TXID: {}, Vout: {}, Amount: {:.8} BTC, Script: {}", txid, vout, amount, hex::encode(script));
                    }
                }
                WalletAction::SpendMultisig => {
                    match spend_p2wpkh(&wallet_state) {
                        Ok((txid, tx_hex)) => {
                            println!("Created P2WPKH -> P2WSH multisig transaction:");
                            println!("TXID: {}", hex::encode(txid));
                            println!("Transaction Hex: {}", tx_hex);
                        }
                        Err(e) => println!("Failed to spend P2WPKH: {:?}", e),
                    }
                }
                WalletAction::SpendOpreturn { txid } => {
                    let txid_bytes = hex::decode(&txid).expect("Invalid TXID hex");
                    let txid_array: [u8; 32] = txid_bytes.try_into().expect("TXID must be 32 bytes");
                    match spend_p2wsh(&wallet_state, txid_array) {
                        Ok(transaction_data) => {
                            let txid2 = hex::encode(&transaction_data[0]);
                            let tx2 = hex::encode(&transaction_data[1]);
                            println!("Created P2WSH -> OP_RETURN transaction:");
                            println!("TXID: {}", txid2);
                            println!("Transaction Hex: {}", tx2);
                        }
                        Err(e) => println!("Failed to spend P2WSH: {:?}", e),
                    }
                }
            }
        }
        Commands::Block { mempool_file, output_file } => {
            let max_block_weight = 4_000_000;
            match parse_mempool(&mempool_file) {
                Ok(mempool_transactions) => {
                    let transaction_order = build_and_sort(&mempool_transactions);
                    let block = select_transactions(transaction_order, &mempool_transactions, max_block_weight);
                    match write_block_to_file(block, &mempool_transactions, &output_file) {
                        Ok(()) => println!("Block written to {}", output_file),
                        Err(e) => println!("Failed to write block: {}", e),
                    }
                }
                Err(e) => println!("Failed to parse mempool: {}", e),
            }
        }
    }
}

// Method                    |    Total Fee | Total Weight | # Transactions | Dependencies OK |   Time (s)
// -----------------------------------------------------------------------------------------------
// Greedy Solution           |      5704530 |      3999904 |           3178 |      true       |     0.0079
// Fractional Knapsack       |      4983743 |      3999696 |           2737 |      true       |     0.0133
// Combined Approach         |      4769114 |      3229332 |           2484 |      true       |     0.0053




// fn main() {
//     let cookie_filepath = "~/.bitcoin/signet/.cookie";
//     dotenv().ok();

//     let extended_private_key =
//         env::var("EXTENDED_PRIVATE_KEY").expect("extended private key url must be set");
//     let wallet_name = env::var("WALLET_NAME").expect("extended private key url must be set");

//     let wallet_state: WalletState =
//         recover_wallet_state(extended_private_key.as_str(), cookie_filepath).unwrap();
//     let balance = wallet_state.balance();

//     println!("{} {:.8}", wallet_name, balance);


//     // Spend from P2WPKH and create a P2WSH multisig output
//     let (txid1, _tx1) = spend_p2wpkh(&wallet_state).unwrap();

//     //spend from the p2wsh multisig output
//     match spend_p2wsh(&wallet_state, txid1) {
//         Ok(transaction_data) => {
//             let _txid2 = hex::encode(&transaction_data[0]); // TXID of the second transaction
//             let tx2 = hex::encode(&transaction_data[1]); // Serialized transaction

//             // println!("Second transaction (P2WSH -> OP_RETURN + Change) created successfully.");
//             // println!("Transaction 2 ID: {}", txid2);
//             println!("{}", tx2);
//         }
//         Err(e) => {
//             println!("Failed to create the second transaction: {:?}", e);
//         }
//     }


//     //block selection 
//     let file_path: &str =
//         "/home/mshallom/Documents/WorkSpaces/Projects/Block-Construction/mempool.csv";
//     let output_path =
//         "/home/mshallom/Documents/WorkSpaces/Projects/Block-Construction/block.txt";
//     let max_block_weight = 4_000_000;

//     let mempool_transaction = parser::parse_mempool(file_path).unwrap();
//     let transaction_order = degraph::build_and_sort(&mempool_transaction);
//     let block = selection::select_transactions(transaction_order, &mempool_transaction, max_block_weight);
//     // dbg!(block);

//     let _ = write::write_block_to_file(block, &mempool_transaction, output_path);


// }

