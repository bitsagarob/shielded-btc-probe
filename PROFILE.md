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
  parentage of section 6. Off-seed derivations use HKDF-SHA256. sk_spend is an
  Fr element reduced from the 32 HKDF bytes. It is only ever used through
  Poseidon, never as a curve scalar.
- Diversified addresses (d, pk_d) with an 11-byte diversifier.
- Leaf derived from public output data and h_body: Poseidon(h_body, j, pk_eph, ct).
- Nullifier bound to the replay-assigned tree position: Poseidon(sk_nf, rho, pos).
- h_body over the canonical body, proof excluded. Output leaves and the proof
  both depend on it.
- Anchor window W = 100, K_min = 1, block-level roots R[h] stored after each block.
- Indexer acceptance order of A.7, with one difference in shape. h_body is not an
  envelope field, so there is no separable binding step. The indexer runs parse,
  canonical re-serialisation, anchor window, root lookup, nullifier uniqueness,
  proof, then mutation. Binding is checked inside the proof step: the statement
  digest the verifier receives is computed from the envelope body and includes
  h_body.
- Sender recovery ciphertext ct_out keyed from vk_out and a digest of the fixed
  output data, one AEAD tag over the batch. Recovery performs the 16.2 leaf check
  and records a sent note only when one of the envelope's nullifiers belongs to
  an owned note.
- Single OP_RETURN carrier, whole envelope in one push.
- Value range is 64 bits per value, checked in circuit. A sum of two inputs or
  two outputs cannot wrap the field.
- Groth16, 192-byte proof, circuit-specific setup.

## Instantiations the paper leaves open

| Item | Paper | Probe |
|---|---|---|
| Curve | unspecified | BLS12-381 for the SNARK, Jubjub for keys and ECDH |
| In-circuit key derivations (sk_nf, vk_in, sk_view) | HKDF-SHA256 | Poseidon. The chain is derived once per transfer from the single sk_spend, so the paper's choice would put three SHA-256 evaluations per transfer in the circuit |
| DiversifyHash | unspecified, must run in-circuit (block 3) | Poseidon(d) as a y coordinate, try-and-increment with witnessed square roots proving each earlier candidate is off-curve, even x, cofactor cleared by three doublings. The search is bounded at 32 candidates. A diversifier with no curve point in 32 tries (probability 2^-32, grindable in tens of core-hours) is not a valid address, and a mint carrying such a d is not anyone's note |
| Note encryption | committing AEAD, gadget unspecified | Poseidon stream cipher (two field elements) plus a Poseidon MAC over key and ciphertext. Key committing by collision resistance |
| Ciphertext size | 67 bytes | 96 bytes (three field elements) |
| Scalars derived from hashes | ScalarFromBytes | low 250 bits of the field element, identical natively and in-circuit |
| h_body | domain-separated hash | Poseidon over length-prefixed 31-byte chunks |
| Public statement | r_anchor, counts, nullifiers, pk_eph, ct, h_body as separate inputs | r_anchor plus one Poseidon digest of all of them. The paper allows this projection (13.2) |
| Arity and padding | deployment-defined; 13.2 says a profile must fix the dummy convention, Appendix A does not | always 2 in, 2 out. A padded input slot is a dummy with v = 0 whose Merkle check is skipped. It still publishes nf = Poseidon(sk_nf, rho(fresh random r_seed), pos = 0) and the indexer inserts that nullifier into the set |
| Input witness | (v, d, r_seed, h_body_create, j, pk_eph, ct, pos, path) per input (14.3) | (v, d, r_seed, h_body_create, j, pos, path) only. pk_eph and ct are recomputed in circuit from the other fields |
| ct_out AEAD | unspecified | ChaCha20-Poly1305, key and nonce from HKDF(vk_out, binding) |

## Departures

- **Trusted setup is a fixed seed.** Every wallet and indexer regenerates the
  same proving and verifying keys from a constant. The toxic waste is public, so
  anyone can forge a proof. This is what makes the probe deployable without a
  ceremony and what makes it worthless outside the signet.
- **Wallet anchor policy is K_wallet = K_min = 1.** The wallet anchors at the
  indexer's replayed height. A.6 recommends a stricter depth for wallets. The
  probe does not do it.
- **Carrier rules beyond the paper.** A carrier transaction has exactly one
  OP_RETURN output with one minimally encoded push. The parsed bytes must
  re-serialise to the published bytes. A transaction with two OP_RETURN outputs,
  or with extra pushes, whose payload starts with the magic is recorded as a
  rejection rather than skipped.
- **Peg-in is a plaintext mint, not a PIPE.** A carrier transaction pays the
  vault and carries a mint envelope with (d, pk_d, r_seed) in the clear. The
  indexer reads the deposited value from the vault output and appends
  Poseidon(v, d, pk_d, r_seed) as a leaf. The circuit accepts either leaf type
  for an input. The deposit amount and the receiving address of a mint are
  public; later transfers are not.
- **Peg-out is a memo plus an operator.** A transfer whose output 0 goes to the
  operator's shielded address may carry a payout request (amount, scriptPubKey)
  in the body, bound by h_body. The operator holds a separate vault key:
  deposits go there, payouts spend it, change returns to it. The operator wallet
  decrypts output 0, checks the request does not exceed it, and pays from the
  vault. The user receives the amount minus the payout transaction fee. A payout
  below 546 sat or to a non-standard script is refused and recorded as failed.
  The payout transaction carries the request's first nullifier in an OP_RETURN,
  so a restored operator wallet can see which requests are already paid and does
  not pay twice. Trust is one key.
- **Envelope carries a payout length byte** after ct_out. Zero when absent.
- **Magic bytes are `sbp`**, not `btc`, so nothing here can be confused with a
  real deployment.
- **Reorganisations rebuild from activation.** State is small on a probe, so the
  indexer discards everything and replays when the stored hash of its tip no
  longer matches the chain.
- **h_aux is not serialised**, matching the paper's current version, and is not
  included in the leaf hash at all rather than as a null constant.

## Known attacks on the probe deployment

- The setup seed is public. Anyone can derive the proving key and forge a
  Groth16 proof for any statement in milliseconds. Every proof the indexer
  accepts is therefore only evidence that someone ran the prover, not that the
  spend was authorised or the values balance.
- A forged transfer with output 0 encrypted to the operator's public shielded
  address plus a payout request drains the vault. The operator wallet decrypts
  output 0, sees a value at least the requested amount, and pays. No secret is
  needed beyond the public seed and the operator's address.
- This is why the deployment must never hold value. Signet coins only.

## Measured (vps2, release build)

| | |
|---|---|
| R1CS constraints, 2 in 2 out | 96,033 |
| Groth16 setup, 1 thread | 11.8 s |
| Groth16 setup, 16 threads | about 2 s |
| Proving key | 56 MB |
| Prove, 1 thread | 9.3 s |
| Prove, 4 threads | 3.1 s |
| Prove, 16 threads | 1.7 to 1.9 s |
| Verify | 2.5 ms |
| Proof | 192 bytes |
| Transfer envelope, no payout | 669 bytes |
| Transfer envelope with a P2WPKH payout | 699 bytes |
| Mint envelope | 81 bytes |
| Carrier transaction, one P2WPKH input, change | 794 vB (669-byte envelope), 824 vB (699), 234 vB (mint) |

The paper's 2-in 2-out estimate is 610 bytes and 625 vB for the OP_RETURN
output alone. The probe's envelope is 59 bytes larger because each ciphertext is
96 bytes instead of 67.
