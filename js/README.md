# js
`shielded-verify.js` is the browser read side of the profile in `../PROFILE.md`: it parses envelopes, recomputes leaves and decrypts with a viewing key, in plain JavaScript.
`vectors-signet.json` and `vectors-mainnet.json` are the data files printed by `sbp export-js`: constants, accepted state and public test vectors (viewing keys and note vectors of the demo wallets, no spending keys).
`node test.mjs js/` runs the vectors through the verifier; `node test-golden.mjs js/` checks it against `../tests/golden-vectors.json`, which the Rust tests pin too.
`sync-webapp.sh [webapp dir]` copies the three files into the bitsaga webapp under their served names (`shielded-verify.js`, `shielded-data.json`, `shielded-data-mainnet.json`) and stamps the source commit into the JS header; the repo is the source, never edit the served copies.
