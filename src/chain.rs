//! Bitcoin side: an Electrum-protocol client for the signet's Fulcrum, and
//! the carrier transaction that publishes an envelope in one OP_RETURN.

use crate::envelope::MAGIC;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute,
    consensus::{deserialize, serialize},
    hashes::{Hash, sha256},
    key::Secp256k1,
    script::{Instruction, PushBytesBuf, PushBytesError},
    secp256k1::{self, Message, SecretKey},
    sighash::{EcdsaSighashType, P2wpkhError, SighashCache},
    transaction,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

pub const DEFAULT_ELECTRUM: &str = "127.0.0.1:50001";
pub const NETWORK: Network = Network::Signet;
pub const FEE_RATE_SAT_VB: u64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("insufficient funds: have {have} sat, need {need} sat")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("fee did not converge")]
    FeeDidNotConverge,
    #[error(transparent)]
    PushBytes(#[from] PushBytesError),
    #[error(transparent)]
    Sighash(#[from] P2wpkhError),
}

fn protocol<E: std::fmt::Display>(e: E) -> Error {
    Error::Protocol(e.to_string())
}

pub struct Electrum {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
}

#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub height: u32,
}

impl Electrum {
    pub fn connect(addr: &str) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        let writer = stream.try_clone()?;
        let mut e = Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 0,
        };
        e.call("server.version", json!(["shielded-probe", "1.4"]))?;
        Ok(e)
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, Error> {
        self.next_id += 1;
        let req = json!({"id": self.next_id, "method": method, "params": params});
        self.writer.write_all(format!("{req}\n").as_bytes())?;
        // Fulcrum pushes headers.subscribe notifications on the same socket;
        // skip anything that is not the reply to this id.
        let v: Value = loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(Error::Protocol("Fulcrum closed the connection".into()));
            }
            let v: Value = serde_json::from_str(&line)?;
            if v.get("id").and_then(|i| i.as_u64()) == Some(self.next_id) {
                break v;
            }
        };
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                return Err(Error::Rpc {
                    code: err["code"].as_i64().unwrap_or(0),
                    message: err["message"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| err.to_string()),
                });
            }
        }
        Ok(v["result"].clone())
    }

    pub fn tip_height(&mut self) -> Result<u32, Error> {
        let v = self.call("blockchain.headers.subscribe", json!([]))?;
        v["height"]
            .as_u64()
            .map(|h| h as u32)
            .ok_or_else(|| protocol("no height in header"))
    }

    pub fn block_hash(&mut self, height: u32) -> Result<bitcoin::BlockHash, Error> {
        let hex = self.call("blockchain.block.header", json!([height]))?;
        let raw = hex::decode(
            hex.as_str()
                .ok_or_else(|| protocol("header not a string"))?,
        )
        .map_err(protocol)?;
        let header: bitcoin::block::Header = deserialize(&raw).map_err(protocol)?;
        Ok(header.block_hash())
    }

    /// All txids of a block, in block order, via transaction.id_from_pos.
    pub fn block_txids(&mut self, height: u32) -> Result<Vec<Txid>, Error> {
        let mut out = Vec::new();
        loop {
            match self.call(
                "blockchain.transaction.id_from_pos",
                json!([height, out.len()]),
            ) {
                Ok(v) => out.push(
                    v.as_str()
                        .ok_or_else(|| protocol("txid not a string"))?
                        .parse()
                        .map_err(protocol)?,
                ),
                Err(Error::Rpc { message, .. })
                    if message.starts_with("No transaction at position") =>
                {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn transaction(&mut self, txid: &Txid) -> Result<Transaction, Error> {
        let hex = self.call("blockchain.transaction.get", json!([txid.to_string()]))?;
        deserialize(
            &hex::decode(hex.as_str().ok_or_else(|| protocol("tx not a string"))?)
                .map_err(protocol)?,
        )
        .map_err(protocol)
    }

    pub fn broadcast(&mut self, tx: &Transaction) -> Result<Txid, Error> {
        let v = self.call(
            "blockchain.transaction.broadcast",
            json!([hex::encode(serialize(tx))]),
        )?;
        v.as_str()
            .ok_or_else(|| protocol("txid not a string"))?
            .parse()
            .map_err(protocol)
    }

    pub fn listunspent(&mut self, spk: &ScriptBuf) -> Result<Vec<Utxo>, Error> {
        let v = self.call(
            "blockchain.scripthash.listunspent",
            json!([scripthash(spk)]),
        )?;
        let arr = v
            .as_array()
            .ok_or_else(|| protocol("listunspent not an array"))?;
        arr.iter()
            .map(|u| {
                Ok(Utxo {
                    outpoint: OutPoint::new(
                        u["tx_hash"]
                            .as_str()
                            .unwrap_or_default()
                            .parse()
                            .map_err(protocol)?,
                        u["tx_pos"].as_u64().unwrap_or(0) as u32,
                    ),
                    value: u["value"].as_u64().unwrap_or(0),
                    height: u["height"].as_u64().unwrap_or(0) as u32,
                })
            })
            .collect()
    }
}

impl Electrum {
    /// Every txid touching a script, confirmed and mempool, oldest first.
    pub fn history(&mut self, spk: &ScriptBuf) -> Result<Vec<Txid>, Error> {
        let v = self.call(
            "blockchain.scripthash.get_history",
            json!([scripthash(spk)]),
        )?;
        let arr = v
            .as_array()
            .ok_or_else(|| Error::Protocol("get_history not an array".into()))?;
        arr.iter()
            .map(|h| {
                h["tx_hash"]
                    .as_str()
                    .unwrap_or_default()
                    .parse()
                    .map_err(|_| Error::Protocol("bad txid in history".into()))
            })
            .collect()
    }
}

pub fn scripthash(spk: &ScriptBuf) -> String {
    let mut h = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

/// A single P2WPKH key that pays for carrier transactions (and, for the
/// operator, holds the vault).
#[derive(Clone)]
pub struct FundingKey {
    pub sk: SecretKey,
}

impl FundingKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, secp256k1::Error> {
        Ok(Self {
            sk: SecretKey::from_slice(b)?,
        })
    }
    pub fn pubkey(&self) -> CompressedPublicKey {
        let secp = Secp256k1::new();
        CompressedPublicKey(self.sk.public_key(&secp))
    }
    pub fn address(&self) -> Address {
        Address::p2wpkh(&self.pubkey(), NETWORK)
    }
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address().script_pubkey()
    }

    /// Builds and signs a transaction: `extra` outputs first, then one
    /// OP_RETURN carrying `payload`, then change back to this key.
    pub fn build_carrier(
        &self,
        utxos: &[Utxo],
        payload: &[u8],
        extra: Vec<TxOut>,
    ) -> Result<Transaction, Error> {
        let spk = self.script_pubkey();
        let extra_total: u64 = extra.iter().map(|o| o.value.to_sat()).sum();
        let op_return = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(payload.to_vec())?),
        };
        // Two passes: size with a zero fee, then re-sign with the real fee.
        let mut fee = 0u64;
        for _ in 0..2 {
            let mut selected = Vec::new();
            let mut total = 0u64;
            for u in utxos {
                selected.push(u.clone());
                total += u.value;
                if total >= extra_total + fee + 546 {
                    break;
                }
            }
            if total < extra_total + fee {
                return Err(Error::InsufficientFunds {
                    have: total,
                    need: extra_total + fee,
                });
            }
            let mut outputs = extra.clone();
            outputs.push(op_return.clone());
            let change = total - extra_total - fee;
            if change >= 546 {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: spk.clone(),
                });
            }
            let mut tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: selected
                    .iter()
                    .map(|u| TxIn {
                        previous_output: u.outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: Witness::new(),
                    })
                    .collect(),
                output: outputs,
            };
            self.sign_p2wpkh(&mut tx, &selected)?;
            let want = tx.vsize() as u64 * FEE_RATE_SAT_VB;
            if fee >= want {
                return Ok(tx);
            }
            fee = want;
        }
        // Fee rose on the second pass (more inputs); one more pass is enough in practice.
        Err(Error::FeeDidNotConverge)
    }

    fn sign_p2wpkh(&self, tx: &mut Transaction, spent: &[Utxo]) -> Result<(), Error> {
        let secp = Secp256k1::new();
        let spk = self.script_pubkey();
        let mut cache = SighashCache::new(tx.clone());
        let mut witnesses = Vec::with_capacity(spent.len());
        for (i, u) in spent.iter().enumerate() {
            let sighash = cache.p2wpkh_signature_hash(
                i,
                &spk,
                Amount::from_sat(u.value),
                EcdsaSighashType::All,
            )?;
            let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &self.sk);
            let sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            witnesses.push(Witness::p2wpkh(&sig, &self.pubkey().0));
        }
        for (i, w) in witnesses.into_iter().enumerate() {
            tx.input[i].witness = w;
        }
        Ok(())
    }
}

/// The OP_RETURN payload of a transaction: Ok(None) when it carries no
/// envelope, Err when an OP_RETURN starts with the magic but the carrier is
/// not exactly one output holding one minimal push.
pub fn op_return_payload(tx: &Transaction) -> Result<Option<Vec<u8>>, &'static str> {
    let outs: Vec<&ScriptBuf> = tx
        .output
        .iter()
        .map(|o| &o.script_pubkey)
        .filter(|s| s.is_op_return())
        .collect();
    let claims = outs.iter().any(|s| {
        s.instructions()
            .nth(1)
            .and_then(|i| i.ok())
            .and_then(|i| i.push_bytes().map(|p| p.as_bytes().starts_with(MAGIC)))
            .unwrap_or(false)
    });
    let fault = |why| if claims { Err(why) } else { Ok(None) };
    let [s] = outs[..] else {
        return if outs.is_empty() {
            Ok(None)
        } else {
            fault("more than one OP_RETURN output")
        };
    };
    let mut instr = s.instructions_minimal().skip(1);
    let payload = match instr.next() {
        Some(Ok(Instruction::PushBytes(p))) => p.as_bytes().to_vec(),
        Some(Err(_)) => return fault("non-minimal push"),
        _ => return fault("OP_RETURN without a push"),
    };
    if instr.next().is_some() {
        return fault("extra data after the envelope push");
    }
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fulcrum_reachable_and_enumerates_blocks() {
        let mut e = Electrum::connect(DEFAULT_ELECTRUM).unwrap();
        let tip = e.tip_height().unwrap();
        assert!(tip > 1000);
        let txids = e.block_txids(100).unwrap();
        assert_eq!(txids.len(), 1);
        let tx = e.transaction(&txids[0]).unwrap();
        assert!(tx.is_coinbase());
        let _ = e.block_hash(100).unwrap();
    }

    #[test]
    fn op_return_extraction() {
        let k = FundingKey::from_bytes(&[9u8; 32]).unwrap();
        let utxos = vec![Utxo {
            outpoint: OutPoint::new(Txid::all_zeros(), 0),
            value: 100_000,
            height: 1,
        }];
        let payload = vec![7u8; 700];
        let tx = k.build_carrier(&utxos, &payload, vec![]).unwrap();
        assert_eq!(op_return_payload(&tx), Ok(Some(payload)));
        assert_eq!(tx.output.len(), 2);
        eprintln!("carrier vsize {} vB for a 700 byte envelope", tx.vsize());
    }
}
