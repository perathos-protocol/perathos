// Node harness for core.js (used by tests/test_site_verifier.py).
//   node node-verify.mjs <extracted pack dir> [expected signer key]
// Prints the verifyPack() result as JSON. Exit code 0 = verified, 1 = failed.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { normalizeEntries, verifyPack } from "./core.js";

function walk(dir, root, out) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, root, out);
    else out.set(relative(root, p).split(sep).join("/"), new Uint8Array(readFileSync(p)));
  }
  return out;
}

const [dir, key] = process.argv.slice(2);
const files = normalizeEntries(walk(dir, dir, new Map()));
const result = await verifyPack(files, { expectedKey: key });
process.stdout.write(JSON.stringify(result, null, 2) + "\n");
process.exitCode = result.valid ? 0 : 1;
