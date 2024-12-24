mod balance;
use std::env;

use balance::recover_wallet_state;
use dotenv::dotenv;

fn main() {
    let cookie_filepath = "~/.bitcoin/signet/.cookie";
    dotenv().ok();

    let extended_private_key =
        env::var("EXTENDED_PRIVATE_KEY").expect("extended private key url must be set");
        let wallet_name =
        env::var("WALLET_NAME").expect("extended private key url must be set");

    let wallet_state =
        recover_wallet_state(extended_private_key.as_str(), cookie_filepath).unwrap();
        let balance = wallet_state.balance();

        println!("{} {:.8}", wallet_name, balance);
}
