// Runs every vector in webapp/shielded-data.json and shielded-data-mainnet.json
// through webapp/shielded-verify.js with plain node (22 or later). Exits
// non-zero on any mismatch.
//
//   node js/test.mjs [path/to/bitsaga/webapp]
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const webapp = process.argv[2] || join(process.env.HOME, "apps/bitsaga/webapp");
const SV = createRequire(import.meta.url)(join(webapp, "shielded-verify.js"));
let ok = true;

for (const file of ["shielded-data.json", "shielded-data-mainnet.json"]) {
  const data = JSON.parse(readFileSync(join(webapp, file), "utf8"));
  const t0 = Date.now();
  const r = await SV.selfTest(data);
  console.log(`${file} (${data.network_label}): vectors ${r.matched}/${r.vectors} matched, ${r.checked} checks, ${Date.now() - t0} ms`);
  for (const f of r.failures) console.log("FAIL " + f);
  ok = ok && r.ok;

  // Carrier path: raw transactions embedded in the data file are checked
  // offline; otherwise the live signet API is asked, and a network failure
  // is a skip, not a fail.
  const events = data.state.events;
  const raw = data.raw_tx || {};
  let n = 0;
  for (const ev of events) {
    let hex = raw[ev.txid];
    if (!hex) {
      if (data.network_label !== "signet") continue;
      try {
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), 8000);
        const res = await fetch("https://signet.bitsaga.be/api/tx-proof?txid=" + ev.txid, { signal: ctl.signal });
        clearTimeout(timer);
        hex = (await res.json()).tx;
      } catch (e) {
        console.log("live tx " + ev.txid.slice(0, 8) + ": skipped (" + e.message + ")");
        continue;
      }
    }
    const payload = SV.opReturnPayload(SV.parseTx(hex));
    if (SV.bytesToHex(payload) !== ev.envelope) {
      ok = false;
      console.log("FAIL opReturnPayload of " + ev.txid + " differs from the accepted envelope");
    }
    n++;
  }
  console.log(`carriers: ${n}/${events.length} parsed, envelopes match`);
}

process.exit(ok ? 0 : 1);
