//! Append-only Poseidon Merkle tree of note leaves (paper section 8).

use crate::{
    Fr, TREE_DEPTH,
    poseidon::{self, tag},
};
use std::collections::HashMap;

pub fn node(l: &Fr, r: &Fr) -> Fr {
    poseidon::hash(tag::NODE, &[*l, *r])
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// nodes[level][index]; level 0 holds leaves, level TREE_DEPTH the root.
    nodes: Vec<HashMap<u64, Fr>>,
    empty: Vec<Fr>,
    len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub pos: u64,
    /// Sibling at each level, leaf level first.
    pub siblings: Vec<Fr>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut empty = vec![Fr::from(0u64)];
        for i in 1..=TREE_DEPTH {
            let prev = empty[i - 1];
            empty.push(node(&prev, &prev));
        }
        Self {
            nodes: vec![HashMap::new(); TREE_DEPTH + 1],
            empty,
            len: 0,
        }
    }

    fn get(&self, level: usize, idx: u64) -> Fr {
        *self.nodes[level].get(&idx).unwrap_or(&self.empty[level])
    }

    pub fn root(&self) -> Fr {
        self.get(TREE_DEPTH, 0)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends a leaf and returns its position.
    pub fn append(&mut self, leaf: Fr) -> u64 {
        let pos = self.len;
        assert!(pos < (1u64 << TREE_DEPTH), "note tree is full");
        self.len += 1;
        self.nodes[0].insert(pos, leaf);
        let mut idx = pos;
        for level in 0..TREE_DEPTH {
            let parent = idx >> 1;
            let l = self.get(level, parent << 1);
            let r = self.get(level, (parent << 1) | 1);
            self.nodes[level + 1].insert(parent, node(&l, &r));
            idx = parent;
        }
        pos
    }

    pub fn leaf(&self, pos: u64) -> Option<Fr> {
        self.nodes[0].get(&pos).copied()
    }

    pub fn path(&self, pos: u64) -> Option<MerklePath> {
        if pos >= self.len {
            return None;
        }
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut idx = pos;
        for level in 0..TREE_DEPTH {
            siblings.push(self.get(level, idx ^ 1));
            idx >>= 1;
        }
        Some(MerklePath { pos, siblings })
    }

    pub fn leaves(&self) -> Vec<Fr> {
        (0..self.len).map(|i| self.get(0, i)).collect()
    }

    /// The tree as it was when it held its first `len` leaves.
    pub fn prefix(&self, len: u64) -> MerkleTree {
        let mut t = MerkleTree::new();
        for i in 0..len.min(self.len) {
            t.append(self.get(0, i));
        }
        t
    }
}

impl MerklePath {
    pub fn root(&self, leaf: &Fr) -> Fr {
        let mut cur = *leaf;
        let mut idx = self.pos;
        for s in &self.siblings {
            cur = if idx & 1 == 0 {
                node(&cur, s)
            } else {
                node(s, &cur)
            };
            idx >>= 1;
        }
        cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_root_matches_tree_root() {
        let mut t = MerkleTree::new();
        let empty_root = t.root();
        for i in 1..=5u64 {
            t.append(Fr::from(i * 1000));
        }
        assert_ne!(t.root(), empty_root);
        for pos in 0..5u64 {
            let p = t.path(pos).unwrap();
            assert_eq!(p.root(&t.leaf(pos).unwrap()), t.root());
            assert_ne!(p.root(&Fr::from(1u64)), t.root());
        }
        assert!(t.path(5).is_none());
        let p = t.prefix(3);
        assert_eq!(p.len(), 3);
        assert_ne!(p.root(), t.root());
        assert_eq!(p.path(2).unwrap().root(&Fr::from(3000u64)), p.root());
        assert_eq!(t.prefix(9).root(), t.root());
    }
}
