//! In-memory chain for tests: blocks of transactions with hashes derived
//! from their contents, a mempool, and listunspent and history read from
//! the transactions themselves.

use super::{ChainSource, Error, Utxo};
use bitcoin::{
    BlockHash, OutPoint, ScriptBuf, Transaction, Txid,
    hashes::{Hash, sha256d},
};

/// Runs once against the chain, from inside a ChainSource call.
pub type Hook = Box<dyn FnOnce(&mut MockChain) + Send>;

pub struct MockChain {
    /// Height of the first stored block; every height below is an empty block.
    base: u32,
    blocks: Vec<Vec<Transaction>>,
    hashes: Vec<BlockHash>,
    pub mempool: Vec<Transaction>,
    /// Runs once, after the next block_txids reply has been computed and
    /// before it is returned.
    pub after_txids: Option<Hook>,
    /// The next broadcast is relayed into the mempool but answered with an
    /// error, as a server whose reply got lost.
    pub drop_next_broadcast_reply: bool,
}

fn out_of_range(height: u32) -> Error {
    Error::Rpc {
        code: 1,
        message: format!("height {height} out of range"),
    }
}

impl MockChain {
    /// A chain of empty blocks up to and including `tip`.
    pub fn new(tip: u32) -> Self {
        Self {
            base: tip + 1,
            blocks: Vec::new(),
            hashes: Vec::new(),
            mempool: Vec::new(),
            after_txids: None,
            drop_next_broadcast_reply: false,
        }
    }

    pub fn tip(&self) -> u32 {
        self.base - 1 + self.blocks.len() as u32
    }

    /// Appends a block and drops its transactions from the mempool. Returns
    /// the new height.
    pub fn mine(&mut self, txs: Vec<Transaction>) -> u32 {
        let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
        self.mempool.retain(|t| !ids.contains(&t.compute_txid()));
        self.blocks.push(txs);
        let i = self.blocks.len() - 1;
        self.rehash(i);
        self.tip()
    }

    /// Replaces the transactions of block `height`; its hash and every hash
    /// above it change.
    pub fn replace(&mut self, height: u32, txs: Vec<Transaction>) {
        let i = (height - self.base) as usize;
        self.blocks[i] = txs;
        self.rehash(i);
    }

    fn rehash(&mut self, from: usize) {
        self.hashes.truncate(from);
        for i in from..self.blocks.len() {
            let prev = if i == 0 {
                Self::empty_hash(self.base - 1)
            } else {
                self.hashes[i - 1]
            };
            let mut e = sha256d::Hash::engine();
            std::io::Write::write_all(&mut e, prev.as_byte_array()).unwrap();
            std::io::Write::write_all(&mut e, &(self.base + i as u32).to_le_bytes()).unwrap();
            for t in &self.blocks[i] {
                std::io::Write::write_all(&mut e, t.compute_txid().as_byte_array()).unwrap();
            }
            self.hashes.push(BlockHash::from_byte_array(
                sha256d::Hash::from_engine(e).to_byte_array(),
            ));
        }
    }

    fn empty_hash(height: u32) -> BlockHash {
        let mut e = sha256d::Hash::engine();
        std::io::Write::write_all(&mut e, b"sbp-mock-empty").unwrap();
        std::io::Write::write_all(&mut e, &height.to_le_bytes()).unwrap();
        BlockHash::from_byte_array(sha256d::Hash::from_engine(e).to_byte_array())
    }

    /// Confirmed transactions with their heights, then the mempool at 0.
    fn all(&self) -> impl Iterator<Item = (&Transaction, u32)> {
        let base = self.base;
        self.blocks
            .iter()
            .enumerate()
            .flat_map(move |(i, b)| b.iter().map(move |t| (t, base + i as u32)))
            .chain(self.mempool.iter().map(|t| (t, 0)))
    }

    fn output(&self, op: &OutPoint) -> Option<&bitcoin::TxOut> {
        self.all()
            .find(|(t, _)| t.compute_txid() == op.txid)
            .and_then(|(t, _)| t.output.get(op.vout as usize))
    }

    fn spent(&self, op: &OutPoint) -> bool {
        self.all()
            .any(|(t, _)| t.input.iter().any(|i| i.previous_output == *op))
    }
}

impl ChainSource for MockChain {
    fn tip_height(&mut self) -> Result<u32, Error> {
        Ok(self.tip())
    }

    fn block_hash(&mut self, height: u32) -> Result<BlockHash, Error> {
        if height > self.tip() {
            return Err(out_of_range(height));
        }
        Ok(match height.checked_sub(self.base) {
            Some(i) => self.hashes[i as usize],
            None => Self::empty_hash(height),
        })
    }

    fn block_txids(&mut self, height: u32) -> Result<Vec<Txid>, Error> {
        if height > self.tip() {
            return Err(out_of_range(height));
        }
        let out = match height.checked_sub(self.base) {
            Some(i) => self.blocks[i as usize]
                .iter()
                .map(Transaction::compute_txid)
                .collect(),
            None => Vec::new(),
        };
        if let Some(f) = self.after_txids.take() {
            f(self);
        }
        Ok(out)
    }

    fn transaction(&mut self, txid: &Txid) -> Result<Transaction, Error> {
        self.all()
            .find(|(t, _)| t.compute_txid() == *txid)
            .map(|(t, _)| t.clone())
            .ok_or_else(|| Error::Rpc {
                code: 2,
                message: "No such mempool or blockchain transaction".into(),
            })
    }

    fn broadcast(&mut self, tx: &Transaction) -> Result<Txid, Error> {
        self.mempool.push(tx.clone());
        if std::mem::take(&mut self.drop_next_broadcast_reply) {
            return Err(Error::Rpc {
                code: -1,
                message: "timeout".into(),
            });
        }
        Ok(tx.compute_txid())
    }

    fn listunspent(&mut self, spk: &ScriptBuf) -> Result<Vec<Utxo>, Error> {
        let mut out = Vec::new();
        for (t, height) in self.all() {
            let txid = t.compute_txid();
            for (vout, o) in t.output.iter().enumerate() {
                let outpoint = OutPoint::new(txid, vout as u32);
                if o.script_pubkey == *spk && !self.spent(&outpoint) {
                    out.push(Utxo {
                        outpoint,
                        value: o.value.to_sat(),
                        height,
                    });
                }
            }
        }
        Ok(out)
    }

    fn history(&mut self, spk: &ScriptBuf) -> Result<Vec<(Txid, i64)>, Error> {
        let mut out = Vec::new();
        for (t, height) in self.all() {
            let pays = t.output.iter().any(|o| o.script_pubkey == *spk);
            let spends = t.input.iter().any(|i| {
                self.output(&i.previous_output)
                    .is_some_and(|o| o.script_pubkey == *spk)
            });
            if pays || spends {
                out.push((t.compute_txid(), i64::from(height)));
            }
        }
        Ok(out)
    }
}
