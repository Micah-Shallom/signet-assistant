mod balance;
use std::env;

use balance::recover_wallet_state;
use dotenv::dotenv;

fn main() {
    let cookie_filepath = "~/.bitcoin/signet/.cookie";
    dotenv().ok();

    let extended_private_key =
        env::var("extended_private_key").expect("extended private key url must be set");

    let wallet_state =
        recover_wallet_state(extended_private_key.as_str(), cookie_filepath).unwrap();
}
