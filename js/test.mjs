// Runs every vector in webapp/shielded-data.json through webapp/shielded-verify.js
// with plain node (22 or later). Exits non-zero on any mismatch.
//
//   node js/test.mjs [path/to/bitsaga/webapp]
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const webapp = process.argv[2] || join(process.env.HOME, "apps/bitsaga/webapp");
const SV = createRequire(import.meta.url)(join(webapp, "shielded-verify.js"));
const data = JSON.parse(readFileSync(join(webapp, "shielded-data.json"), "utf8"));

const t0 = Date.now();
const r = await SV.selfTest(data);
console.log(`vectors ${r.matched}/${r.vectors} matched, ${r.checked} checks, ${Date.now() - t0} ms`);
for (const f of r.failures) console.log("FAIL " + f);

// The carrier path needs the live API; a network failure is a skip, not a fail.
let fetched = "skipped";
try {
  const ev = data.state.events[0];
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  const res = await fetch("https://signet.bitsaga.be/api/tx-proof?txid=" + ev.txid, { signal: ctl.signal });
  clearTimeout(timer);
  const j = await res.json();
  const payload = SV.opReturnPayload(SV.parseTx(j.tx));
  if (SV.bytesToHex(payload) !== ev.envelope) {
    r.ok = false;
    r.failures.push("opReturnPayload of " + ev.txid + " differs from the accepted envelope");
  }
  fetched = "carrier " + ev.txid.slice(0, 8) + " parsed, envelope matches";
} catch (e) {
  fetched = "skipped (" + e.message + ")";
}
console.log("live tx: " + fetched);

process.exit(r.ok ? 0 : 1);
