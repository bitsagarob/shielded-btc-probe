# Runs

Every public run of the probe, with the transactions it produced, and the two
review passes between them. The deployment profile of each run is committed
under `deployments/`. All amounts are satoshi.

## Bitsaga Signet, first run (24 September 2026, activation 151315)

| Step | Height | Transaction |
|---|---|---|
| Mint 500,000 to alice | 151315 | `19430eee67e1dd4ea2006c792925641ac1951cb76aeb719a6ef773b1614d5882` |
| Mint 300,000 to bob | 151315 | `542495b5acac32a167a7396fe6cda1f1588c1a76f4dcc0797da9ec9ba33a7a64` |
| alice pays bob 120,000 shielded, 669-byte envelope | 151317 | `0f82be9d47c6610d497e108c3170321ab4ae69d79d5cca005594cad20809f046` |
| same envelope republished (double spend) | 151318 | `6d7381f07278dbfe5d0cc52fe9ef796af37b4e82d50c885af0a8293e3a00af61` rejected: nullifier already spent |
| bob redeems 400,000 spending two notes, 699-byte envelope | 151320 | `c0a74fc9967bfccb40b13412a59295576c1b862b4360c35151fe8df138b26343` |
| operator pays 400,000 to alice's signet address | 151321 | `99314a8ad3bfe17b92b810b04a9942e238d9f43decaaa2598f2b54ad669bb8f6` |
| malformed envelope with the right magic | 151321 | `08c1ca27c381dcacf7384cd2acb00677d59932dec2ac08636783b155390fc0d7` rejected: parse |

## Hardening pass

A review against the paper after the first run found and fixed these.

- Dummy input slots publish a real nullifier, Poseidon(sk_nf, rho(fresh r_seed), 0), and the indexer inserts it, so padding follows one fixed convention.
- Sender-side recovery performs the paper's 16.2 leaf check and records a sent note only when one of the envelope's nullifiers is ours.
- The carrier parser rejects, and logs, transactions with two OP_RETURN outputs or extra pushes when the payload starts with the magic, and requires parsed bytes to re-serialise to the published bytes.
- The operator holds a separate vault key, deducts the payout transaction fee from the user's amount, refuses payouts below 546 sat or to a non-standard script, and tags each payout with the request's first nullifier so a restored operator wallet does not pay twice.
- DiversifyHash is bounded at 32 candidates; a diversifier with no curve point is not a valid address.
- `sbp unlock` clears the lock that a failed or unconfirmed send leaves on its input notes.
- A vault history entry counts as a paid request only when the transaction spends a vault output and is confirmed, or is one this wallet broadcast; anyone can pay the vault and echo a nullifier in an OP_RETURN.
- A chain error, an empty vault or a fee that does not converge leaves a payout request pending for the next run; only the request itself (over the burn, below dust, non-standard script, below fee) is refused and recorded.
- Output 0 of a payout-carrying transfer is marked burned only in the operator wallet; any other recipient keeps the note.
- PROFILE.md records the corrected witness list, the 64-bit value range, the wallet anchor policy and the attacks the public setup allows.

## Bitsaga Signet, second run (24 September 2026, activation 151455)

| Step | Height | Transaction |
|---|---|---|
| Mint 500,000 to alice | 151456 | `abc8ba527c6b84d5bb2d6ae067ba354a84d669a3500efe43ad060687ac684f97` |
| Mint 300,000 to bob | 151456 | `4c28f72f2e079d2ed25b3e899d702424f9d1e3d21b2f6eafbd30e96ef766e0c2` |
| alice pays bob 120,000 shielded, 669-byte envelope | 151459 | `1ffa8dd59d1ccdaf43ca15e6f8bf04e151e1e77c30e9be0efc654f355f0a4c73` |
| bob redeems 400,000 spending two notes, 699-byte envelope | 151460 | `08d4707d2db63f410a17b03dbb00538e8ca7581728771a20c14f0897c3cc9a0f` |
| operator pays 399,632 (400,000 minus the 368 sat fee) from the vault key | 151461 | `85a6d93d6f4d07fabfa901936a5fb58711e013e07067d6ad23aea1eb3679df25` |
| same transfer envelope republished | 151461 | `776ccb9b4bce353a60d70feda6ece200aa8e54f95baaf8b54fe9cb5603dee272` rejected: nullifier already spent |

Both wallets held notes from the first deployment; on their first scan against
the new history they detected the changed event log and rescanned from
activation. The operator's scan records the burned 400,000 sat output as spent.

## Alignment pass (25 September 2026)

A second audit, of every normative statement and default in the paper's
sections 5 to 16 and Appendix A, is section 1 of PROFILE.md. It changed the
counts to CompactSize, put const_salt under h_body and const_salt plus
aux_null in the leaf hash, made sk_spend a Jubjub scalar whose canonical bytes
feed sk_nf and vk_in, and gave the wallet the A.6 anchor policy K_WALLET = 2,
so a note is spendable one block after the block that created it. Envelope
sizes did not change; the circuit is 96,039 constraints. The three departures
that stay (HKDF-SHA256 key chain, 67-byte byte AEAD, byte-hash DiversifyHash)
are costed in PROFILE.md section 2.

## Bitcoin (25 September 2026, activation 968530, fee rate 3 sat/vB)

Profile: `deployments/mainnet.json`. Every transaction is public on
mempool.space.

| Step | Height | Transaction |
|---|---|---|
| Mint 15,000 to alice, 81-byte envelope, fee 702 sat | 968530 | `3529901cc6b914e04bd9ec1c242ec9527ac0cea0dfa64cc2516da56a24e8d49e` |
| Mint 10,000 to bob | 968530 | `1a467ebf7ae1cbea3612ba84676ded33ad2be65e1d9f725687deda91902708e5` |
| alice pays bob 5,000 shielded, 669-byte envelope, 793 vB, fee 2,382 sat | 968533 | `5c3a5857e9fe9aa98ccb18e52b1a229fcac542caf4e46b499de8efd4bdec3751` |
| bob redeems 12,000 spending two notes, 699-byte envelope, 892 vB, fee 2,676 sat | 968537 | `515a51d7c197d52c10a772dbd23fa401177d4d52ab758819963c33afed78fa49` |
| operator pays 11,448 (12,000 minus the 552 sat fee) with `payouts --only` | 968538 | `2e21f3f9c1241f02abf62cd1e0cf4cfeb14b8c39b3c09bfb659a6cf733faa1d4` |

Wallets under the K_WALLET = 2 policy waited two blocks after each note before
spending it. The 669-byte OP_RETURN was relayed by mempool.space.

## Bitsaga Signet, third run under the aligned profile (25 September 2026, activation 152595)

Profile: `deployments/signet.json`.

| Step | Height | Transaction |
|---|---|---|
| Mint 500,000 to alice | 152597 | `86e0a657198d14ced368ce793d5c5048ed7e2dc14b164712fbdd78458c12fd2e` |
| Mint 300,000 to bob | 152597 | `a1b28f50dfb61d6121b8e81d42e9221d2e9cd236972b1e81d2b19e3132cb2574` |
| alice pays bob 120,000, 669-byte envelope | 152599 | `8be6d3b052bfaf9a8e65a3d3805aecb2e34f525206f5a0ecdb5b1484490916ac` |
| bob redeems 400,000, 699-byte envelope | 152601 | `93ff54d7e6b57202d1a064c5bc41e4855e9bb042add198a8760721411bee873f` |
| operator pays 399,632 | 152603 | `43aa5749078cbfee57d7f532fd07a182089b2d1954e2f42871cc4b68856f1d66` |
| transfer envelope republished | 152603 | `bd2121237df3b42675b140f9019b6fc6fe278d7dddd290ed4df6246a4343b296` rejected: nullifier already spent |

The indexer reads the chain through Fulcrum's Electrum protocol
(`transaction.id_from_pos` enumerates each block), so it needs no node RPC.
