# Signet Assistant

A command-line utility for managing Bitcoin Signet wallets and constructing optimized blocks from mempool data. This tool is designed for developers, Bitcoin enthusiasts, and small-scale miners working with the Signet test network. It allows users to recover wallet states, perform SegWit transactions (including multisig and OP_RETURN outputs), and build fee-optimized blocks from a mempool CSV file.

## Table of Contents
- [Signet Assistant](#signet-assistant)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Available Commands](#available-commands)
    - [Wallet Commands](#wallet-commands)
    - [Block Command](#block-command)
  - [Examples](#examples)
    - [Recover Wallet State](#recover-wallet-state)
    - [Spend to Multisig](#spend-to-multisig)
    - [Spend from Multisig to OP\_RETURN](#spend-from-multisig-to-op_return)
    - [Build Optimized Block](#build-optimized-block)
  - [Dependencies](#dependencies)
  - [Contributing](#contributing)

## Prerequisites

Before using the Signet Assistant, ensure you have the following:
- Rust and Cargo installed on your system.
- A running Bitcoin Signet node with the cookie file located at `~/.bitcoin/signet/.cookie`.
- The `bitcoin-cli` command available in your PATH.
- A mempool CSV file (if using the block command for block construction).

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Micah-Shallom/signet-assistant.git
   cd signet-assistant
   ```

2. Set up the `.env` file:
   Create a `.env` file in the project root with the following variables:
   ```
   EXTENDED_PRIVATE_KEY=your_extended_private_key_here
   WALLET_NAME=your_wallet_name_here
   ```
   - `EXTENDED_PRIVATE_KEY`: Your wallet's extended private key for deriving child keys.
   - `WALLET_NAME`: A name or identifier for your wallet.

3. Ensure the Signet cookie file is in the correct location:
   The cookie file should be at `~/.bitcoin/signet/.cookie`. If it's located elsewhere, update the `cookie_filepath` variable in `main.rs`.

## Available Commands

The Signet Assistant provides the following commands, all prefixed with `cargo run`:

### Wallet Commands
- `cargo run wallet recover`: Recovers and displays the wallet state, including the balance and list of UTXOs.
- `cargo run wallet spend-multisig`: Spends from a P2WPKH UTXO to create a 2-of-2 P2WSH multisig output.
- `cargo run wallet spend-opreturn <txid>`: Spends from a P2WSH multisig output to an OP_RETURN output with a custom message (e.g., "Shallom Micah Bawa").

### Block Command
- `cargo run block <mempool_file> <output_file>`: Builds an optimized block from the provided mempool CSV file and writes the selected transaction IDs to the specified output file.

## Examples

Below are examples of how to use each command:

### Recover Wallet State
```bash
cargo run wallet recover
```
This command will display the wallet's balance and list its UTXOs, for example:
```
Wallet: MySignetWallet
Balance: 0.50000000 BTC
UTXOs: 2
- TXID: abcdef123456..., Vout: 0, Amount: 0.30000000 BTC, Script: 0014...
- TXID: fedcba654321..., Vout: 1, Amount: 0.20000000 BTC, Script: 0014...
```

### Spend to Multisig
```bash
cargo run wallet spend-multisig
```
This command creates a transaction that spends from a P2WPKH UTXO to a 2-of-2 P2WSH multisig output. It will print the transaction ID and hex:
```
Created P2WPKH -> P2WSH multisig transaction:
TXID: 1234abcd...
Transaction Hex: 02000000...
```

### Spend from Multisig to OP_RETURN
First, obtain the TXID from the multisig transaction created above. Then, use it to spend to an OP_RETURN output:
```bash
cargo run wallet spend-opreturn 1234abcd...
```
This will create a transaction spending from the P2WSH multisig to an OP_RETURN output (embedding a custom message) and a change output. It will print the new transaction ID and hex:
```
Created P2WSH -> OP_RETURN transaction:
TXID: 5678efgh...
Transaction Hex: 02000000...
```

### Build Optimized Block
To build an optimized block from a mempool CSV file and write it to `block.txt`:
```bash
cargo run block mempool.csv block.txt
```
This command will parse `mempool.csv`, select transactions to maximize fees within the 4,000,000 weight limit, and write the block to `block.txt`. It will also display statistics:
```
Total transactions: 3178
Total fee: 5704530
Total weight: 3999904
Average fee per weight: 1.43
```

## Dependencies

The project relies on the following external crates:
- `clap`: For parsing command-line arguments.
- `dotenv`: For loading environment variables from a .env file.
- `csv`: For parsing the mempool CSV file.
- `hex-literal`: For handling hexadecimal literals.
- `hmac`: For HMAC operations in key derivation.
- `num-bigint`: For big integer operations in cryptography.
- `num-traits`: For numerical traits.
- `ripemd`: For RIPEMD-160 hashing.
- `secp256k1`: For elliptic curve operations (ECDSA signatures).
- `serde_json`: For parsing JSON data from `bitcoin-cli`.
- `sha2`: For SHA-256 and SHA-512 hashing.
- `std`: Standard library components.

These dependencies are managed via `Cargo.toml`.

## Contributing

If you encounter any issues or have suggestions for improvements, please:
- Open an issue on the GitHub repository.
- Submit a pull request with your proposed changes.

Your contributions are welcome and appreciated!

