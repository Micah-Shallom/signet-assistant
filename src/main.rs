mod balance;
mod spend_funds;
use std::env;
use crate::balance::balance::WalletState;

use balance::balance::recover_wallet_state;
use dotenv::dotenv;
use spend_funds::spend::spend_p2wpkh;

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
    let (txid1, tx1) = spend_p2wpkh(&wallet_state).unwrap();
}
