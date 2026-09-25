# shielded-btc-probe

An implementation of the transfer layer from [Shielded Bitcoin: Private
Transfers on the Bitcoin L1](https://www.allocinit.xyz/uploads/shielded-bitcoin.pdf) (Shikhelman,
Komarov, Moskvin, 24 September 2026): notes, nullifiers, a Groth16 transfer
proof, OP_RETURN publication, deterministic replay, wallet scanning and sender
recovery, on Bitcoin and on the Bitsaga Signet. The Groth16 setup is derived
from a public seed, so anyone can forge a proof: never hold value with it.

## Build and run

```
cargo build --release
./target/release/sbp init --wallet state/alice.json
./target/release/sbp mint --wallet state/alice.json --amount 500000
./target/release/sbp sync
./target/release/sbp scan --wallet state/alice.json
./target/release/sbp send --wallet state/alice.json --to <sbp1...> --amount 120000
```

`init` prints a funding address to pay first. `params/` (Groth16 keys,
generated on first use from the fixed seed) and `state/` (wallets, indexer
state) are ignored by git. `sbp --help` lists the remaining commands.

## Replay a deployment

Anyone can rebuild the accepted history from a deployment profile and any
Electrum server that speaks plain TCP; no operator key is needed.

```
cp deployments/signet.json state/deployment.json
./target/release/sbp sync --electrum <host:port>
./target/release/sbp status
```

`sync` replays every block from activation, verifies each envelope against
the verifying key regenerated from the fixed seed and writes
`state/state.json`. `status` prints the accepted events and the rejections.
Two replays of the same profile against different servers print the same list.

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
| `js/` | browser verifier, see `js/README.md` |

## Documents

- `PROFILE.md`, normative: the profile, every departure from the paper and its cost.
- `RUNS.md`: every public run with its transactions.
- `SECURITY.md` and `js/README.md`.
