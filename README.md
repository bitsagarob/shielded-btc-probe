# shielded-probe

A working implementation of the transfer layer from "Shielded Bitcoin: Private
Transfers on the Bitcoin L1" (Shikhelman, Komarov, Moskvin, 24 September 2026),
running against the Bitsaga Signet. Notes, nullifiers, a Groth16 transfer proof,
OP_RETURN publication, deterministic replay, wallet scanning and sender
recovery are all real. The peg is a toy and the trusted setup is public.
PROFILE.md lists every deviation from the paper.

## What it proved on chain (24 September 2026, Bitsaga Signet)

| Step | Height | Transaction |
|---|---|---|
| Deployment activation | 151315 | |
| Mint 500,000 sat to alice | 151315 | `19430eee67e1dd4ea2006c792925641ac1951cb76aeb719a6ef773b1614d5882` |
| Mint 300,000 sat to bob | 151315 | `542495b5acac32a167a7396fe6cda1f1588c1a76f4dcc0797da9ec9ba33a7a64` |
| alice pays bob 120,000 shielded, 669-byte envelope | 151317 | `0f82be9d47c6610d497e108c3170321ab4ae69d79d5cca005594cad20809f046` |
| same envelope republished (double spend) | 151318 | `6d7381f07278dbfe5d0cc52fe9ef796af37b4e82d50c885af0a8293e3a00af61` rejected: nullifier already spent |
| bob redeems 400,000 spending two notes, 699-byte envelope | 151320 | `c0a74fc9967bfccb40b13412a59295576c1b862b4360c35151fe8df138b26343` |
| operator pays 400,000 sat to alice's signet address | 151321 | `99314a8ad3bfe17b92b810b04a9942e238d9f43decaaa2598f2b54ad669bb8f6` |
| malformed envelope with the right magic | 151321 | `08c1ca27c381dcacf7384cd2acb00677d59932dec2ac08636783b155390fc0d7` rejected: parse |

## Second run, after the hardening pass (24 September 2026, activation 151455)

| Step | Height | Transaction |
|---|---|---|
| Mint 500,000 sat to alice | 151456 | `abc8ba527c6b84d5bb2d6ae067ba354a84d669a3500efe43ad060687ac684f97` |
| Mint 300,000 sat to bob | 151456 | `4c28f72f2e079d2ed25b3e899d702424f9d1e3d21b2f6eafbd30e96ef766e0c2` |
| alice pays bob 120,000 shielded, 669-byte envelope, 1.97 s proof | 151459 | `1ffa8dd59d1ccdaf43ca15e6f8bf04e151e1e77c30e9be0efc654f355f0a4c73` |
| bob redeems 400,000 spending two notes, 699-byte envelope | 151460 | `08d4707d2db63f410a17b03dbb00538e8ca7581728771a20c14f0897c3cc9a0f` |
| operator pays 399,632 sat (400,000 minus the 368 sat fee) from the vault key | 151461 | `85a6d93d6f4d07fabfa901936a5fb58711e013e07067d6ad23aea1eb3679df25` |
| same transfer envelope republished | 151461 | `776ccb9b4bce353a60d70feda6ece200aa8e54f95baaf8b54fe9cb5603dee272` rejected: nullifier already spent |

Both wallets had notes from the first deployment; on the first scan against the
new history they detected the changed event log and rescanned from activation.
The operator's scan records the burned 400,000 sat output as spent.

## Bitcoin mainnet (25 September 2026, activation 968530, fee rate 3 sat/vB)

Profile as committed in `deployments/mainnet.json`. Every transaction is public on
mempool.space.

| Step | Height | Transaction |
|---|---|---|
| Mint 15,000 sat to alice, 81-byte envelope, fee 702 sat | 968530 | `3529901cc6b914e04bd9ec1c242ec9527ac0cea0dfa64cc2516da56a24e8d49e` |
| Mint 10,000 sat to bob | 968530 | `1a467ebf7ae1cbea3612ba84676ded33ad2be65e1d9f725687deda91902708e5` |
| alice pays bob 5,000 shielded, 669-byte envelope, 793 vB, fee 2,382 sat, proof 1.89 s | 968533 | `5c3a5857e9fe9aa98ccb18e52b1a229fcac542caf4e46b499de8efd4bdec3751` |
| bob redeems 12,000 spending two notes, 699-byte envelope, 892 vB, fee 2,676 sat | 968537 | `515a51d7c197d52c10a772dbd23fa401177d4d52ab758819963c33afed78fa49` |
| operator pays 11,448 sat (12,000 minus the 552 sat fee) with `payouts --only` | mempool | `2e21f3f9c1241f02abf62cd1e0cf4cfeb14b8c39b3c09bfb659a6cf733faa1d4` |

Wallets with the K_wallet = 2 policy waited two blocks after each note before
spending it. The 669-byte OP_RETURN relayed to mempool.space within seconds.

## Signet, third run under the aligned profile (25 September 2026, activation 152595)

| Step | Height | Transaction |
|---|---|---|
| Mint 500,000 sat to alice | 152597 | `86e0a657198d14ced368ce793d5c5048ed7e2dc14b164712fbdd78458c12fd2e` |
| Mint 300,000 sat to bob | 152597 | `a1b28f50dfb61d6121b8e81d42e9221d2e9cd236972b1e81d2b19e3132cb2574` |
| alice pays bob 120,000, 669 bytes, proof 1.92 s | 152599 | `8be6d3b052bfaf9a8e65a3d3805aecb2e34f525206f5a0ecdb5b1484490916ac` |
| bob redeems 400,000, 699 bytes, proof 1.95 s | 152601 | `93ff54d7e6b57202d1a064c5bc41e4855e9bb042add198a8760721411bee873f` |
| operator pays 399,632 sat | 152603 | `43aa5749078cbfee57d7f532fd07a182089b2d1954e2f42871cc4b68856f1d66` |
| transfer envelope republished | 152603 | `bd2121237df3b42675b140f9019b6fc6fe278d7dddd290ed4df6246a4343b296` rejected: nullifier already spent |

The indexer reads the chain through Fulcrum's Electrum protocol
(`transaction.id_from_pos` enumerates each block), so it needs no node RPC.

## Hardening pass

A review against the paper after the first on-chain run found and fixed these.
Dummy input slots now publish a real nullifier, Poseidon(sk_nf, rho(fresh r_seed), 0), and the indexer inserts it, so padding follows one fixed convention.
Sender-side recovery now performs the paper's 16.2 leaf check and only records a sent note when one of the envelope's nullifiers is ours.
The carrier parser now rejects, and logs, transactions with two OP_RETURN outputs or extra pushes when the payload starts with the magic, and requires parsed bytes to re-serialise to the published bytes.
The operator now holds a separate vault key, deducts the payout transaction fee from the user's amount, refuses payouts below 546 sat or to a non-standard script, and tags each payout with the request's first nullifier so a restored operator wallet does not pay twice.
DiversifyHash is bounded at 32 candidates; a diversifier with no curve point is not a valid address.
`sbp unlock` clears the lock that a failed or unconfirmed send leaves on its input notes.
A vault history entry counts as a paid request only when the transaction spends a vault output and is confirmed, or is one this wallet broadcast; anyone can pay the vault and echo a nullifier in an OP_RETURN.
A chain error, an empty vault or a fee that does not converge leaves a payout request pending for the next run; only the request itself (over the burn, below dust, non-standard script, below fee) is refused and recorded.
Output 0 of a payout-carrying transfer is marked burned only in the operator wallet; any other recipient keeps the note.
PROFILE.md records the corrected witness list, the 64-bit value range, the wallet anchor policy and the attacks the public setup allows.

## Alignment pass (25 September 2026)

A second audit, this time of every normative statement and default in the
paper's sections 5 to 16 and Appendix A, is the first section of PROFILE.md.
It changed the counts to CompactSize, put const_salt under h_body and
const_salt plus aux_null in the leaf hash, made sk_spend a Jubjub scalar whose
canonical bytes feed sk_nf and vk_in, and gave the wallet the A.6 anchor
policy: K_WALLET = 2, so a note is spendable one block after the block that
created it. Envelope sizes did not change; the circuit is 96,039 constraints.
The three departures that stay (HKDF-SHA256 key chain, 67-byte byte AEAD,
byte-hash DiversifyHash) are measured in PROFILE.md section 2: 2.6x to 8.2x
the constraints each, 19.7x together.

## Run it

```
cargo build --release
./target/release/sbp bench
./target/release/sbp init --wallet state/operator.json
./target/release/sbp deploy --activation <tip+2> --operator-wallet state/operator.json
./target/release/sbp init --wallet state/alice.json
# fund the printed funding address from the faucet, then:
./target/release/sbp mint --wallet state/alice.json --amount 500000
./target/release/sbp sync
./target/release/sbp scan --wallet state/alice.json
./target/release/sbp send --wallet state/alice.json --to <sbp1...> --amount 120000
./target/release/sbp redeem --wallet state/bob.json --amount 400000 --to <tb1...>
./target/release/sbp payouts --wallet state/operator.json
./target/release/sbp publish-raw --wallet state/alice.json --hex <envelope hex>
```

`params/` holds the Groth16 keys (56 MB, generated on first use from a fixed
seed). `state/` holds wallets and the indexer state. Both are ignored by git.
`send` and `redeem` anchor one block below the replayed tip, so a note minted
or received in block h can be spent once the indexer has replayed block h + 1.

On a bitcoin deployment two commands change: `mint` refuses an amount over
100,000 sat unless `--i-know` is passed, and `payouts` runs only with
`--only <txid>`, once per request the operator has verified.

## Replay it yourself

Anyone can rebuild the accepted history from the deployment profile and any
Electrum server; no key of the operator is needed.

```
cargo build --release
./target/release/sbp deploy --activation <height> --network <signet|bitcoin> --fee-rate <sat/vB> --operator-wallet <wallet>
./target/release/sbp sync --electrum <host:port>
./target/release/sbp status
```

`deploy` writes `state/deployment.json`: network, fee rate, activation
height, the vault scriptPubKey, the operator's shielded address and the
fingerprint of the verifying key. That file is the whole profile and holds no
secret. `deploy` derives the vault and the operator address from the operator
wallet, so an outsider does not run it: copy the published `deployment.json`
into `state/` and start at `sync`. The profile of a public run is committed
to this repository next to the table it produced.

`sync` replays every block from activation over Electrum's
`transaction.id_from_pos`, verifies every envelope against the Groth16
verifying key regenerated from the fixed seed (refusing a `params/` whose
fingerprint differs from the profile) and writes `state/state.json`.
`status` prints the accepted events and the rejections. Two replays of the
same profile against different servers must print the same list.

The client speaks the Electrum protocol over plain TCP only. `--electrum`
defaults to `127.0.0.1:50001` for signet and `127.0.0.1:50011` for bitcoin. A
server that only offers TLS needs a local stunnel (or any TLS-terminating
proxy) in front of it, with `--electrum` pointed at the plain port.

## Layout

| File | Paper section |
|---|---|
| `src/keys.rs` | 6, key hierarchy, diversified addresses, DiversifyHash |
| `src/note.rs` | 5, 9, 12, notes, encryption, leaves, nullifiers |
| `src/tree.rs` | 8, the note tree |
| `src/envelope.rs` | 11, 13, A.3, A.5, canonical bytes, h_body, statement digest |
| `src/circuit.rs` | 14, B, the transfer relation |
| `src/prover.rs` | Groth16 |
| `src/chain.rs` | A.4, Electrum client and the OP_RETURN carrier |
| `src/indexer.rs` | 8, 15, A.6, A.7, replay |
| `src/wallet.rs` | 10, 16, construction, scanning, recovery |
