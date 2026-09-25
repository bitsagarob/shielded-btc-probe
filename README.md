# shielded-probe

A working implementation of the transfer layer from "Shielded Bitcoin: Private
Transfers on the Bitcoin L1" (Shikhelman, Komarov, Moskvin, 24 September 2026),
running against the Bitsaga Signet. Notes, nullifiers, a Groth16 transfer proof,
OP_RETURN publication, deterministic replay, wallet scanning and sender
recovery are all real. The peg is a toy and the trusted setup is public.
PROFILE.md lists every deviation from the paper.

RUNS.md lists every public run with its transactions.

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
