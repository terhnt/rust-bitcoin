// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use prelude::*;

use core::default::Default;

use hashes::hex::{HexIterator, Error as HexError};
use hashes::sha256d;
use blockdata::opcodes;
use blockdata::script;
use blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn};
use blockdata::block::{Block, BlockHeader};
use network::constants::Network;
use util::uint::Uint256;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 60 * 3;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 130; // 0x82
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 30; // 0x1E
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 68; // 0x44
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 30; // 0x1E
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;


/// In Unobtaniumd this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF).unwrap() << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    250_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(504365055)
                                          .push_scriptint(4)
                                          .push_slice(b"San Francisco plaza evacuated after suspicious package is found")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: vec![],
    });

    // Outputs
    let script_bytes: Result<Vec<u8>, HexError> =
        HexIterator::new("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap()
            .collect();
    let out_script = script::Builder::new()
        .push_slice(script_bytes.unwrap().as_slice())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 1 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1375548986,
                    bits: 0x1e0fffff,
                    nonce: 1211565
                },
                txdata,
            }
        }
        Network::Testnet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1531487000,
                    bits: 0x1e0fffff,
                    nonce: 1746468
                },
                txdata,
            }
        }
        Network::Signet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1598918400,
                    bits: 0x1e0377ae,
                    nonce: 52613770
                },
                txdata,
            }
        }
        Network::Regtest => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1375548985,
                    bits: 0x207fffff,
                    nonce: 1
                },
                txdata,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use core::default::Default;
    use hashes::hex::FromHex;

    use network::constants::Network;
    use consensus::encode::serialize;
    use blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Default::default());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   Vec::from_hex("04ffff001d01043f53616e204672616e636973636f20706c617a612065766163756174656420616674657220737573706963696f7573207061636b61676520697320666f756e64").unwrap());

        assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   Vec::from_hex("04ffff001d01043f53616e204672616e636973636f20706c617a612065766163756174656420616674657220737573706963696f7573207061636b61676520697320666f756e64").unwrap());
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(format!("{:x}", gen.wtxid()),
                   "36a192e90f70131a884fe541a1e8a5643a28ba4cb24cbb2924bd0ee483f7f484".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                   "36a192e90f70131a884fe541a1e8a5643a28ba4cb24cbb2924bd0ee483f7f484".to_string());
        assert_eq!(gen.header.time, 1375548986);
        assert_eq!(gen.header.bits, 0x1e0fffff);
        assert_eq!(gen.header.nonce, 1211565);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "000004c2fc5fffb810dccc197d603690099a68305232e552d96ccbe8e2c52b75".to_string());
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                  "36a192e90f70131a884fe541a1e8a5643a28ba4cb24cbb2924bd0ee483f7f484".to_string());
        assert_eq!(gen.header.time, 1531487000);
        assert_eq!(gen.header.bits, 0x1e0fffff);
        assert_eq!(gen.header.nonce, 1746468);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "000007b02afb00ae826d948d88f4973c00073425f965917f6298b6d280bde021".to_string());
    }

    //#[test]
    //fn signet_genesis_full_block() {
    //    let gen = genesis_block(Network::Signet);
    //    assert_eq!(gen.header.version, 1);
    //    assert_eq!(gen.header.prev_blockhash, Default::default());
    //    assert_eq!(format!("{:x}", gen.header.merkle_root),
    //              "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
    //    assert_eq!(gen.header.time, 1598918400);
    //    assert_eq!(gen.header.bits, 0x1e0377ae);
    //    assert_eq!(gen.header.nonce, 52613770);
    //    assert_eq!(format!("{:x}", gen.header.block_hash()),
    //               "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string());
    //}
}

