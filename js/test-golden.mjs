// Checks shielded-verify.js against tests/golden-vectors.json, the same file
// the Rust test golden_vectors_match pins. Poseidon constants come from the
// exported data file; every expected value comes from the golden file.
//
//   node js/test-golden.mjs [webapp dir] [golden json]
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webapp = process.argv[2] || join(process.env.HOME, "apps/bitsaga/webapp");
const goldenPath = process.argv[3] || join(here, "..", "tests", "golden-vectors.json");
const SV = createRequire(import.meta.url)(join(webapp, "shielded-verify.js"));
const data = JSON.parse(readFileSync(join(webapp, "shielded-data.json"), "utf8"));
const G = JSON.parse(readFileSync(goldenPath, "utf8"));
SV.load(data);

const fails = [];
let n = 0;
const eq = (label, got, want) => { n++; if (got !== want) fails.push(`${label}: got ${got}, golden ${want}`); };
const hex = SV.bytesToHex, bytes = SV.hexToBytes;
const fr = h => BigInt("0x" + hex(bytes(h).reverse()));
const T = data.tags;

eq("fr_modulus", data.fr_modulus, G.fr_modulus);
eq("poseidon LEAF(1,2)", SV.frToHex(SV.poseidon(T.LEAF, [1n, 2n])), G.poseidon.leaf_1_2);
eq("diversify_hash base", SV.pointToHex(SV.diversifyHash(bytes(G.diversify.d))), G.diversify.base);

const env = SV.parseEnvelope(bytes(G.envelope.bytes));
eq("envelope reserialises", hex(env.bytes), G.envelope.bytes);
eq("envelope length", env.bytes.length, G.envelope.len);
eq("h_anchor", env.hAnchor, 0x01020304);
eq("payout amount", env.payout.amount, 1000n);
const hb = SV.hBody(env);
eq("h_body", SV.frToHex(hb), G.envelope.h_body);
eq("leaf j=1", SV.frToHex(SV.leaf(hb, 1, env.pkEph[1], env.ct[1])), G.note.leaf_j1);
eq("pk_eph[0]", SV.pointToHex(env.pkEph[0]), G.note.pk_eph);
eq("ct[0]", hex(bytes(G.note.ct)), G.note.ct);

const wide = SV.parseEnvelope(bytes(G.envelope.wide_payout_bytes));
eq("wide payout h_body", SV.frToHex(SV.hBody(wide)), G.envelope.wide_payout_h_body);
eq("wide payout CompactSize form", wide.bytes[6 + 4 + 2 + 64 + 64 + 192 + data.envelope.ct_out_len], 0xfd);
eq("no-payout parses", SV.parseEnvelope(bytes(G.envelope.no_payout_bytes)).payout, null);

const menv = SV.parseEnvelope(bytes(G.envelope.mint_bytes));
eq("mint kind", menv.kind, "mint");
eq("mint_leaf", SV.frToHex(SV.mintLeaf(1234n, menv.d, menv.pkD, menv.rSeed)), G.note.mint_leaf);
eq("address text", SV.addressString(menv.d, menv.pkD), G.address.text);
eq("mint owned by alice", SV.decryptAsRecipient(menv, G.keys.vk_in).length, 1);
eq("mint not owned by bob", SV.decryptAsRecipient(menv, G.keys.bob_vk_in).length, 0);
eq("nullifier pos 7", SV.frToHex(SV.poseidon(T.NF, [fr(G.keys.sk_nf), fr(G.note.rho), 7n])), G.note.nullifier_pos7);

function checkNote(label, got, want) {
  eq(label + " count", got.length, 1);
  if (!got.length) return;
  eq(label + " j", got[0].j, want.j);
  eq(label + " v", got[0].v, BigInt(want.v));
  eq(label + " d", hex(got[0].d), want.d);
  eq(label + " r_seed", SV.frToHex(got[0].rSeed), want.r_seed);
}
checkNote("bob as recipient", SV.decryptAsRecipient(env, G.envelope.outputs[0].recipient_vk_in), G.envelope.outputs[0]);
checkNote("alice as recipient", SV.decryptAsRecipient(env, G.envelope.outputs[1].recipient_vk_in), G.envelope.outputs[1]);
eq("bob cannot open output 1", SV.decryptAsRecipient(env, G.keys.bob_vk_in).filter(x => x.j === 1).length, 0);

// Merkle root, sparse append-only tree as tree.rs: pins NODE tag and left/right order.
function merkleRoot(leaves, depth) {
  const node = (l, r) => SV.poseidon(T.NODE, [l, r]);
  const empty = [0n];
  for (let i = 1; i <= depth; i++) empty.push(node(empty[i - 1], empty[i - 1]));
  let level = new Map(leaves.map((x, i) => [i, x]));
  const paths = leaves.map(() => []);
  for (let l = 0; l < depth; l++) {
    const next = new Map();
    for (const [idx] of level) {
      const p = idx >> 1;
      if (next.has(p)) continue;
      const L = level.get(2 * p) ?? empty[l], R = level.get(2 * p + 1) ?? empty[l];
      next.set(p, node(L, R));
    }
    leaves.forEach((_, i) => { const idx = i >> l; paths[i].push(level.get(idx ^ 1) ?? empty[l]); });
    level = next;
  }
  return { root: level.get(0) ?? empty[depth], empty: empty[depth], paths };
}
const m = merkleRoot(G.merkle.leaves.map(fr), 32);
eq("empty root", SV.frToHex(m.empty), G.merkle.empty_root);
eq("root of five", SV.frToHex(m.root), G.merkle.root);
eq("siblings at pos 2", m.paths[2].map(SV.frToHex).join(","), G.merkle.path_siblings.join(","));

const sender = await SV.decryptAsSender(env, G.keys.vk_out);
eq("sender recovers both", sender.length, 2);
sender.forEach(s => {
  const w = G.envelope.outputs[s.j];
  eq(`sender output ${s.j} v`, s.v, BigInt(w.v));
  eq(`sender output ${s.j} to`, s.to, w.to);
});
eq("bob's vk_out opens nothing", (await SV.decryptAsSender(env, "00".repeat(32))).length, 0);

console.log(`golden: ${n} checks, ${fails.length} failures`);
for (const f of fails) console.log("FAIL " + f);
process.exit(fails.length ? 1 : 0);
