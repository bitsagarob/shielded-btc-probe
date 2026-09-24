# Probe profile: what differs from the paper

This crate implements the transfer layer of "Shielded Bitcoin: Private Transfers
on the Bitcoin L1" (Shikhelman, Komarov, Moskvin, [[alloc] init], 24 September
2026). The paper leaves the concrete hash functions, the encryption gadget, the
curve and the proof backend to an implementation profile. This file lists every
choice made here and every place where the probe departs from the text.

## Fixed by the paper and followed

- Note plaintext is (v, d, r_seed). rho and sk_eph are derived from r_seed, never
  stored.
- Key hierarchy: sk_master, sk_spend, sk_nf, vk_in, sk_view, vk_out with the
  parentage of section 6. Off-seed derivations use HKDF-SHA256.
- Diversified addresses (d, pk_d) with an 11-byte diversifier.
- Leaf derived from public output data and h_body: Poseidon(h_body, j, pk_eph, ct).
- Nullifier bound to the replay-assigned tree position: Poseidon(sk_nf, rho, pos).
- h_body over the canonical body, proof excluded. Output leaves and the proof
  both depend on it.
- Anchor window W = 100, K_min = 1, block-level roots R[h] stored after each block.
- Indexer acceptance order of A.7: parse, binding, anchor window, nullifier
  uniqueness, proof, then mutate.
- Sender recovery ciphertext ct_out keyed from vk_out and a digest of the fixed
  output data, one AEAD tag over the batch.
- Single OP_RETURN carrier, whole envelope in one push.
- Groth16, 192-byte proof, circuit-specific setup.

## Instantiations the paper leaves open

| Item | Paper | Probe |
|---|---|---|
| Curve | unspecified | BLS12-381 for the SNARK, Jubjub for keys and ECDH |
| In-circuit key derivations (sk_nf, vk_in, sk_view) | HKDF-SHA256 | Poseidon. The paper's chain would put three SHA-256 evaluations per input in the circuit |
| DiversifyHash | unspecified, must run in-circuit (block 3) | Poseidon(d) as a y coordinate, try-and-increment with witnessed square roots proving each earlier candidate is off-curve, even x, cofactor cleared by three doublings |
| Note encryption | committing AEAD, gadget unspecified | Poseidon stream cipher (two field elements) plus a Poseidon MAC over key and ciphertext. Key committing by collision resistance |
| Ciphertext size | 67 bytes | 96 bytes (three field elements) |
| Scalars derived from hashes | ScalarFromBytes | low 250 bits of the field element, identical natively and in-circuit |
| h_body | domain-separated hash | Poseidon over length-prefixed 31-byte chunks |
| Public statement | r_anchor, counts, nullifiers, pk_eph, ct, h_body as separate inputs | r_anchor plus one Poseidon digest of all of them. The paper allows this projection (13.2) |
| Arity | deployment-defined | always 2 in, 2 out. Unused inputs are dummies with v = 0 whose Merkle check is skipped |
| ct_out AEAD | unspecified | ChaCha20-Poly1305, key and nonce from HKDF(vk_out, binding) |

## Departures

- **Trusted setup is a fixed seed.** Every wallet and indexer regenerates the
  same proving and verifying keys from a constant. The toxic waste is public, so
  anyone can forge a proof. This is what makes the probe deployable without a
  ceremony and what makes it worthless outside the signet.
- **Peg-in is a plaintext mint, not a PIPE.** A carrier transaction pays the
  vault (one P2WPKH key held by the operator) and carries a mint envelope with
  (d, pk_d, r_seed) in the clear. The indexer reads the deposited value from the
  vault output and appends Poseidon(v, d, pk_d, r_seed) as a leaf. The circuit
  accepts either leaf type for an input. The deposit amount and the receiving
  address of a mint are public; later transfers are not.
- **Peg-out is a memo plus an operator.** A transfer whose output 0 goes to the
  operator's shielded address may carry a payout request (amount, scriptPubKey)
  in the body, bound by h_body. The operator wallet decrypts output 0, checks the
  request does not exceed it, and pays from the vault. Trust is one key.
- **Envelope carries a payout length byte** after ct_out. Zero when absent.
- **Magic bytes are `sbp`**, not `btc`, so nothing here can be confused with a
  real deployment.
- **Reorganisations rebuild from activation.** State is small on a probe, so the
  indexer discards everything and replays when the stored hash of its tip no
  longer matches the chain.
- **h_aux is not serialised**, matching the paper's current version, and is not
  included in the leaf hash at all rather than as a null constant.

## Measured (vps2, 16 threads, release build)

| | |
|---|---|
| R1CS constraints, 2 in 2 out | 95,525 |
| Groth16 setup | about 2 s |
| Proving key | 56 MB |
| Prove | 1.7 to 1.9 s |
| Verify | 2.5 ms |
| Proof | 192 bytes |
| Transfer envelope, no payout | 669 bytes |
| Transfer envelope with a P2WPKH payout | 699 bytes |
| Mint envelope | 81 bytes |
| Carrier transaction, one P2WPKH input, change | 794 vB (669-byte envelope), 824 vB (699), 234 vB (mint) |

The paper's 2-in 2-out estimate is 610 bytes and 625 vB for the OP_RETURN
output alone. The probe's envelope is 59 bytes larger because each ciphertext is
96 bytes instead of 67.
