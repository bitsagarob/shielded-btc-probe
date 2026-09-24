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

The indexer reads the chain through Fulcrum's Electrum protocol
(`transaction.id_from_pos` enumerates each block), so it needs no node RPC.

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
