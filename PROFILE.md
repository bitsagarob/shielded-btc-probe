# Probe profile: conformance to the paper

This crate implements the transfer layer of "Shielded Bitcoin: Private Transfers
on the Bitcoin L1" (Shikhelman, Komarov, Moskvin, [[alloc] init], 24 September
2026). Section 1 is the audit of every normative statement and recommended
default in the paper's sections 5 to 16 and Appendix A against the code, after
the alignment pass of 25 September 2026. Section 2 lists what still departs and
what closing each departure costs, measured on this box. Section 3 is what the
probe adds outside the paper and the attacks its public setup allows.

Status legend: **ok** the code does what the paper says; **open** the paper
leaves the choice to the profile and this is the choice; **differs** the code
does something else (see section 2).

## 1. Conformance

| # | Item | Paper | Code | Status |
|---|---|---|---|---|
| 1 | Wallet seed | 32 uniformly random bytes (A.2) | `keys.rs:179` `seed: [u8; 32]`, `wallet.rs` fills it from the OS RNG | ok |
| 2 | Diversifier | 11 bytes (A.2) | `keys.rs:20` `DIVERSIFIER_LEN = 11` | ok |
| 3 | Body order | header, h_anchor, N, M, nf, pk_eph, ct_note, ct_out, then proof (A.3, 13.1) | `envelope.rs:108` `body_bytes`, proof appended in `to_bytes` | ok, plus a payout field after ct_out (section 3) |
| 4 | Header | 6 bytes: magic, version, type, one more byte (A.3, A.4) | `envelope.rs:87` magic(3) version(1) kind(1) reserved(1) | ok |
| 5 | Magic bytes | `btc` (A.4 size estimate) | `envelope.rs:12` `sbp` | differs, deliberate |
| 6 | Version, type | version 1, transfer type 0x01 | `envelope.rs:13,14` | ok |
| 7 | h_anchor | uint32 little-endian block height (A.3, A.4) | `envelope.rs:111` | ok |
| 8 | Counts | canonical CompactSize, non-minimal rejected (A.5) | `envelope.rs:92` writer, `envelope.rs:308` reader rejects wide forms | ok |
| 9 | Nullifiers | 32-byte fixed-width canonical field elements (A.4, A.5) | `envelope.rs:233` `fr_from_bytes` rejects values at or above the modulus | ok |
| 10 | pk_eph | one compressed canonical point encoding, 32 bytes (A.4, A.5) | `envelope.rs:237` arkworks compressed Edwards; re-serialisation check catches a free sign bit | ok |
| 11 | ct_note length | 67 bytes: 8 v, 11 d, 32 r_seed, 16 tag (A.4) | `note.rs:35` 96 bytes, three field elements | differs |
| 12 | ct_out layout | (pk_d, sk_eph) per output, 64 bytes each, one 16-byte tag over the batch: 144 bytes for M = 2 (A.3, A.4, 12.2) | `envelope.rs:18` `CT_OUT_LEN = N_OUT * 64 + 16`, `note.rs:218` | ok |
| 13 | Proof | 192 bytes, Groth16 (A.4, 22.1) | `prover.rs:124` compressed BLS12-381 proof, `envelope.rs:16` | ok |
| 14 | Carrier | exactly one OP_RETURN output with the whole envelope, witness bytes ignored, oversized invalid (A.4) | `chain.rs:272` one minimal push; `chain.rs:357` parser | ok, stricter (section 3) |
| 15 | Canonical rules | fixed LE integers, CompactSize counts, fixed-width field elements, one point encoding, fixed ct length, index order, reject shorter, longer, non-minimal, reordered, undecodable (A.5) | `envelope.rs:211` parse, `envelope.rs:284` trailing bytes, `envelope.rs:286` must re-serialise to the published bytes | ok |
| 16 | Anchor window | W = 100, K_min = 1, H - W <= h_anchor <= H - 1 (A.6) | `lib.rs:32,33`, `indexer.rs:332` | ok |
| 17 | Wallet anchor depth | K_wallet > K_min recommended, one common policy (A.6) | `lib.rs:36` `K_WALLET = 2`, `wallet.rs:543` anchors at R[H + 1 - K_WALLET] | ok |
| 18 | Retained roots | R[h] stored after each block, carried forward when empty (8, 15) | `indexer.rs:276` | ok |
| 19 | Acceptance order | parse, binding, anchor, nullifiers, proof, then mutate (A.7, 15) | `indexer.rs:302` carrier and parse, `:332` window, `:340` root, `:342` duplicate, `:346` spent, `:354` proof, `:361` mutate | ok; binding is inside the proof step (item 30) |
| 20 | Note plaintext | (v, d, r_seed) (5) | `note.rs` `NotePlaintext` | ok |
| 21 | rho | H_rho(r_seed), domain separated (5) | `note.rs:73` Poseidon tag RHO | open, Poseidon |
| 22 | sk_eph | ScalarFromBytes(H_eph(r_seed)) (5) | `note.rs:79,83` low 250 bits of Poseidon tag EPH | open, Poseidon and truncation |
| 23 | pk_eph | [sk_eph] G_d (5, 12.1) | `note.rs:119`, `circuit.rs:178` | ok |
| 24 | sk_master | HKDF_master(seed) (Table 1) | `keys.rs:201` HKDF-SHA256 info `sbp/master` | ok |
| 25 | sk_spend | ScalarFromBytes(HKDF_spend(sk_master)), a scalar (Table 1) | `keys.rs:202` Jubjub scalar reduced from HKDF-SHA256 | ok |
| 26 | sk_spend^ser | BytesFromScalar(sk_spend) feeds the children (Table 1, 9) | `keys.rs:55` canonical 32 bytes LE, `keys.rs:64` read as the field element the circuit sees | ok |
| 27 | sk_nf, vk_in | HKDF_nf, HKDF_in of sk_spend^ser (Table 1), derived in circuit (9, B block 4) | `keys.rs:228,231`, `circuit.rs:226,227` Poseidon over the scalar's bytes | differs, HKDF is Poseidon |
| 28 | vk_out | HKDF_out(sk_master) (Table 1) | `keys.rs:203` HKDF-SHA256 info `sbp/out` | ok |
| 29 | sk_view | ScalarFromBytes(HKDF_view(vk_in)) (eq. 1), in circuit (9) | `keys.rs:234`, `circuit.rs:228` Poseidon, low 250 bits | differs, HKDF is Poseidon |
| 30 | G_d, pk_d | G_d = DiversifyHash(d), pk_d = [sk_view] G_d (eq. 1) | `keys.rs:138` Poseidon try-and-increment, `keys.rs:238`, `circuit.rs:113,263` | open, DiversifyHash unspecified |
| 31 | Leaf | H_leaf(const_salt, h_body, j, pk_eph, ct_note, h_aux) (9) | `note.rs:169`, `circuit.rs:265`: Poseidon over exactly those nine elements | ok |
| 32 | const_salt | fixed protocol constant (9, 13.3) | `note.rs:39` `sbp/const_salt/1`, 16 bytes | ok, value is the profile's |
| 33 | h_aux | aux_null, not serialised (9, 22.5) | `note.rs:46` zero, absorbed in every leaf | ok |
| 34 | Nullifier | H_nf(BytesToField(sk_nf), BytesToField(rho), pos) (9) | `note.rs:201`, `circuit.rs:304` Poseidon tag NF; sk_nf and rho are already field elements | ok |
| 35 | Ownership rule | pk_d re-derived from sk_spend and d in circuit and used in the input ciphertext relation (9, B block 3) | `circuit.rs:263,264` | ok |
| 36 | sk_nf not a free witness | derived from sk_spend in circuit (9, 14.3) | `circuit.rs:226` | ok |
| 37 | Note key schedule | from the ECDH shared secret and pk_eph (12.1) | `note.rs:107` Poseidon(KDF, shared, pk_eph), `circuit.rs:190` | ok, hash open |
| 38 | Recipient AEAD | committing, key private (A.1, A6) | `note.rs:111` Poseidon stream cipher plus Poseidon MAC over key and ciphertext | open, see section 2 |
| 39 | ct_out binding digest | from output count, ordered pk_eph and ct_note (12.2, 13.1) | `envelope.rs:177` SHA-256(M, pk_eph[], ct[]) | ok |
| 40 | ct_out KDF | vk_out-based, digest in, AEAD key and nonce out; digest is the associated data (12.2) | `note.rs:205` HKDF-SHA256(ikm vk_out, salt digest), `note.rs:218` AAD digest | ok |
| 41 | ct_out AEAD | confidential, ciphertext-integrity, key private (A6) | `note.rs:218` ChaCha20-Poly1305 | open, not key committing (section 2) |
| 42 | ct_out before h_body | ct_out finalised first (12, 13.1) | `wallet.rs:646` then `:651` | ok |
| 43 | Assembly order | inputs, outputs, recovery ct, body and h_body, prove and publish (13.1) | `wallet.rs:531` `build_transfer`, `wallet.rs:672` `send` | ok |
| 44 | Input preparation | reconstruct each input leaf and verify against the stored leaf; nullifiers absent from N and distinct (13.1, C.4) | `wallet.rs:582` leaf check, `:630` distinct, `:633` not replayed | ok |
| 45 | h_body | H_body(const_salt || canonical body), proof excluded (13.3) | `envelope.rs:142` Poseidon over the salted body bytes | ok, hash open |
| 46 | Public statement | (r_anchor, N, M, nf[], pk_eph[], ct[], h_body) (14.2); a verifier may project it (13.2) | `circuit.rs:59` r_anchor plus one Poseidon digest of the rest, `envelope.rs:159` | ok, projected |
| 47 | Input witness | (v, d, r_seed, h_body_create, j, pk_eph, ct_note, pos, path) (14.3) | `circuit.rs:30` without pk_eph and ct_note, which the circuit derives from the others | differs in shape, same relation |
| 48 | Output witness | (v, d, pk_d, r_seed) (14.3) | `circuit.rs:43` | ok |
| 49 | One sk_spend | single witness for all inputs (14.3) | `circuit.rs:52` | ok |
| 50 | Excluded witness values | no precomputed leaves, nullifiers, rho, sk_eph, sk_nf (14.3) | all derived in `circuit.rs` | ok |
| 51 | Arity | deployment fixes it; padded slots need a fixed dummy convention (13.2, 14.3, 22.1) | `lib.rs:29` always 2 in 2 out; a dummy input has v = 0, fresh r_seed, no Merkle check, publishes its nullifier (`circuit.rs:300`, `wallet.rs:591`) | ok |
| 52 | Value range | canonical satoshi range, sums do not wrap (B blocks 6, 7) | `circuit.rs:254,322` 64 bits per value, `:333` | ok |
| 53 | Merkle membership | under r_anchor, real inputs only (B block 2) | `circuit.rs:300` | ok |
| 54 | Envelope binding | proof bound to h_body (B block 8) | `circuit.rs:344` h_body inside the digest; `tests/unconstrained_public_input.rs` | ok |
| 55 | Recipient checks | decrypt, d to local path, pk_eph = [sk_eph] G_d, leaf equals the replayed leaf (16.1) | `wallet.rs:361` leaf of every output, `note.rs:151` pk_eph, `wallet.rs:366` | ok |
| 56 | Sender recovery | digest, key and nonce, decrypt ct_out, per output decrypt ct_note, same checks (16.2) | `wallet.rs:393,397`, `note.rs:164` | ok, plus a nullifier guard (section 3) |
| 57 | Shared validation | parse, magic and version, vector lengths, points decode, h_body recomputed (15) | `envelope.rs:211`, digest recomputed in `indexer.rs:349` | ok |
| 58 | Reorganisation | replay is over the active chain; rebuild (15) | `indexer.rs:237` replays from activation | ok |
| 59 | Proof re-randomisation | a re-randomised copy is a nullifier replay; txid bookkeeping is a deployment concern (14.3 note, 22.1) | `indexer.rs:346`; the wallet's lock is keyed by txid and released by the nullifier set (`wallet.rs:287`) | ok |
| 60 | Proof system | Groth16, circuit-specific setup (A.1, 22.1) | `prover.rs:68`; setup seed is public | ok, insecure setup (section 3) |
| 61 | Curve, hash, backend | left to the profile (A.1) | BLS12-381 Groth16, Jubjub keys, Poseidon width 3 rate 2 over Fr (`poseidon.rs`) | open |

## 2. Remaining departures and what closing them costs

Baseline after the alignment pass: 96,039 constraints, proving 1.9 s on 16
threads and 9.5 s on one, 56 MB proving key. Groth16 proving scales close to
linearly in constraints, so the times below are the constraint ratio applied
to the baseline. Constraint counts were measured with the arkworks SHA-256
gadget (39,738 constraints per compression) by `tests/gadget_costs.rs`:

```
cargo test --release --test gadget_costs -- --ignored --nocapture
```

| Departure | Paper | Cost to close | Proving time after |
|---|---|---|---|
| (a) sk_nf, vk_in, sk_view are Poseidon of sk_spend in circuit (items 27, 29) | HKDF-SHA256 of BytesFromScalar(sk_spend), Table 1 | three HKDF-SHA256 in circuit, once per transfer: 696,223 constraints, total 792,262 (8.2x) | about 16 s on 16 threads, 78 s on one |
| (b) ct_note is 96 bytes of Poseidon stream cipher plus MAC (item 11, 38) | 67-byte committing byte AEAD | a byte AEAD (two SHA-256 keystream blocks, SHA-256 tag) per output and per re-encrypted input: 160,194 each, 640,776 per transfer, total 736,815 (7.7x); a SHA-256 note KDF over the two points adds 74,886 each, 299,544 per transfer | about 15 s and 71 s; with the KDF 21 s and 100 s |
| (c) DiversifyHash seeds the search with Poseidon(d) (item 30) | unspecified; a byte hash would match the rest of the paper's defaults | SHA-256(d) in place of Poseidon(d), four times per transfer: 39,724 against 237 each, plus 157,948 per transfer, total 253,987 (2.6x) | about 5 s and 25 s |
| All three | | 1,890,000 constraints (19.7x), proving key about 1.1 GB | about 37 s and 3 min |
| Magic `sbp` (item 5) | `btc` | three bytes, no other change | none |
| Input witness carries no pk_eph or ct_note (item 47) | listed in 14.3 | about 15 lines and 10 constraints to witness both and enforce equality with the derived values; the relation does not change | none |
| ct_out AEAD is not key committing (item 41) | A6 asks only for confidentiality, integrity and key privacy of this channel; A.1 asks the profile for a committing AEAD in general | the padding fix (32 zero bytes under the AEAD) makes ChaCha20-Poly1305 key committing: 6 lines and 32 more bytes on the wire, breaking the 144-byte figure of A.4 | none |
| Recipient AEAD committing by collision resistance, not a proven committing AEAD (item 38) | committing AEAD | covered by (b) | see (b) |

The magic stays `sbp` on purpose: the setup is public (section 3), so nothing
this probe publishes must ever be parsed by an indexer of a real deployment.
The witness shape and the ct_out padding are left as they are because neither
changes what the proof or the recovery channel guarantees.

The instantiations the paper leaves open, in one place:

| Item | Probe |
|---|---|
| Curve | BLS12-381 for the SNARK, Jubjub for keys and ECDH |
| Poseidon | width 3, rate 2, 8 full and 57 partial rounds, alpha 5, one domain tag absorbed first (`poseidon.rs`) |
| ScalarFromBytes | mod the group order for sk_spend (native only); low 250 bits of the field element for sk_eph and sk_view (native and in circuit alike) |
| DiversifyHash | y = Poseidon(DIVERSIFY, d) + k for k = 0, 1, ... until (y^2 - 1)(d y^2 + 1) is a square; even x; cofactor cleared by three doublings; the circuit checks every earlier candidate is off-curve through a witnessed non-residue root; bounded at 32 candidates, so a d with no point in 32 tries (probability 2^-32) is not a valid address |
| Recipient AEAD | c_i = m_i + Poseidon(STREAM, key, i) over the two elements (v || d, r_seed); tag = Poseidon(MAC, key, c0, c1) |
| h_body | Poseidon(BODY) over const_salt || body, length-prefixed 31-byte chunks |
| Public statement | r_anchor plus Poseidon(STMT, h_body, N, M, nf[], pk_eph[], ct[]) |
| HKDF labels | `sbp/master`, `sbp/spend`, `sbp/out`, `sbp/diversifier`, `sbp/ctout/key`, `sbp/ctout/nonce` |
| const_salt | the 16 bytes `sbp/const_salt/1` |

## 3. Outside the paper

- **Trusted setup is a fixed seed** (`prover.rs:21`). Every wallet and indexer
  regenerates the same keys from a constant. The toxic waste is public, so
  anyone can forge a proof. This is what makes the probe deployable without a
  ceremony and worthless outside the signet.
- **Peg-in is a plaintext mint.** A carrier pays the vault and carries a mint
  envelope (kind 0x02) with (d, pk_d, r_seed) in the clear. The indexer reads
  the deposited value from the vault output and appends Poseidon(MINT_LEAF, v,
  d, pk_d, r_seed). The circuit accepts either leaf type for an input.
- **Peg-out is a memo plus an operator.** A transfer whose output 0 goes to the
  operator's shielded address may carry a payout request (amount,
  scriptPubKey) after ct_out, length-prefixed with a CompactSize, zero when
  absent, bound by h_body. The operator decrypts output 0, checks the request
  does not exceed it, refuses dust and non-standard scripts, pays from a
  separate vault key minus the payout fee, and tags the payout with the
  request's first nullifier so a restored operator wallet does not pay twice.
- **Carrier rules beyond A.4.** Two OP_RETURN outputs, extra pushes or a
  non-minimal push whose payload starts with the magic are recorded as
  rejections rather than skipped, so probing them leaves a trace.
- **Sender recovery only for own spends.** A sent record is written only when
  one of the envelope's nullifiers belongs to a note of this wallet, so a
  holder of vk_out alone cannot forge outgoing history.
- **Reorganisations rebuild from activation.** State is small on a probe.
- **Wallet anchor policy.** K_WALLET = 2: a transfer built at replayed height
  H anchors at R[H - 1], so a note becomes spendable one block after the block
  that created it. The wallet rebuilds the tree prefix of that height from the
  replayed leaves and checks it against the stored root.

### Known attacks on this deployment

- The setup seed is public. Anyone can derive the proving key and forge a
  Groth16 proof for any statement in seconds. An accepted proof is evidence
  that someone ran the prover, not that the spend was authorised.
- A forged transfer with output 0 encrypted to the operator's public address
  plus a payout request drains the vault. Nothing beyond the public seed and
  the operator's address is needed.
- This is why the deployment must never hold value. Signet coins only.

## 4. Measured (vps2, release build, 25 September 2026)

| | |
|---|---|
| R1CS constraints, 2 in 2 out | 96,039 |
| Groth16 setup, 1 thread | 12.2 s |
| Groth16 setup, 16 threads | 3.1 s |
| Proving key | 56 MB |
| Prove, 1 thread | 9.5 to 9.8 s |
| Prove, 16 threads | 1.7 to 1.9 s |
| Verify | 2.5 ms |
| Proof | 192 bytes |
| Transfer envelope, no payout | 669 bytes |
| Transfer envelope with a P2WPKH payout | 699 bytes |
| Mint envelope | 81 bytes |
| Carrier transaction, one P2WPKH input, change | 794 vB (669-byte envelope), 824 vB (699), 234 vB (mint) |

The paper's 2-in 2-out estimate is 610 bytes and 625 vB for the OP_RETURN
output alone. The probe's envelope is 59 bytes larger: 58 because each
ciphertext is 96 bytes instead of 67, and 1 for the payout length.
