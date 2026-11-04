// Browser UI for the Perathos evidence verifier. All checks live in core.js.
import { normalizeEntries, setEd25519Fallback, verifyPack } from "./core.js";

const NOBLE_URL = "https://cdn.jsdelivr.net/npm/@noble/ed25519@2.1.0/index.js";
const SAMPLE_URL = "../samples/sample-evidence-pack.zip";
const MAX_ZIP_BYTES = 50 * 1024 * 1024;
const MAX_ENTRY_BYTES = 100 * 1024 * 1024;

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const resultEl = $("result");
const keyEl = $("key");
let lastFiles = null;
let lastName = "";

// ---- Ed25519 backend --------------------------------------------------------
// Prefer WebCrypto; load @noble/ed25519 only if this browser lacks Ed25519.
const RFC8032_PUB = new Uint8Array([
  0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
  0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
]);
const backendReady = (async () => {
  try {
    await crypto.subtle.importKey("raw", RFC8032_PUB, { name: "Ed25519" }, false, ["verify"]);
    return "WebCrypto";
  } catch {
    const ed = await import(NOBLE_URL);
    // zip215: false = strict RFC 8032 checks, matching WebCrypto and the Python CLI.
    setEd25519Fallback((sig, msg, pub) => ed.verifyAsync(sig, msg, pub, { zip215: false }));
    return "@noble/ed25519";
  }
})();

// ---- Loading ----------------------------------------------------------------
function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.classList.toggle("error", isError);
}

async function unzip(buf) {
  if (typeof JSZip === "undefined") throw new Error("JSZip did not load (check your connection or content blocker)");
  if (buf.byteLength > MAX_ZIP_BYTES) throw new Error("this file is larger than 50 MB; use the CLI for big packs");
  const zip = await JSZip.loadAsync(buf);
  const entries = new Map();
  let total = 0;
  for (const entry of Object.values(zip.files)) {
    if (entry.dir) continue;
    const data = await entry.async("uint8array");
    total += data.byteLength;
    if (total > MAX_ENTRY_BYTES) throw new Error("the pack expands to more than 100 MB; use the CLI");
    entries.set(entry.name, data);
  }
  return normalizeEntries(entries);
}

async function loadBuffer(buf, name) {
  resultEl.hidden = true;
  setStatus(`Checking ${name} ...`);
  try {
    const files = await unzip(buf);
    lastFiles = files;
    lastName = name;
    await run();
  } catch (e) {
    lastFiles = null;
    setStatus(`Could not read ${name}: ${e.message || e}`, true);
  }
}

async function run() {
  if (!lastFiles) return;
  const key = keyEl.value.trim().toLowerCase();
  if (key && !/^[0-9a-f]{64}$/.test(key)) {
    setStatus("The expected signer key must be 64 hexadecimal characters.", true);
    resultEl.hidden = true;
    return;
  }
  try {
    const backend = await backendReady;
    const result = await verifyPack(lastFiles, { expectedKey: key || undefined });
    render(result, backend);
    setStatus("");
  } catch (e) {
    setStatus(`Verification could not run: ${e.message || e}`, true);
  }
}

// ---- Rendering ----------------------------------------------------------------
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
const code = (t) => el("code", {}, t ?? "none");

function render(r, backend) {
  const s = r.stats;
  resultEl.replaceChildren();

  resultEl.append(
    el("div", { class: `banner ${r.valid ? "ok" : "fail"}` },
      el("strong", {}, r.valid ? "VERIFIED" : "FAILED"),
      el("span", {}, r.valid
        ? `${lastName}: every check passed.`
        : `${lastName}: ${r.errors.length} problem(s) found. The first: ${r.errors[0]}`)),
  );

  const keyInput = keyEl.value.trim();
  const signerText = s.signers.length ? s.signers.join(", ") : "none";
  const dl = el("dl", { class: "facts" });
  const fact = (k, ...v) => dl.append(el("dt", {}, k), el("dd", {}, ...v));
  fact("Session", code(s.session_id));
  fact("Recorded", `${s.first_ts || "?"} to ${s.last_ts || "?"} (local clock)`);
  fact("Tool calls", String(s.tool_calls));
  fact("Blocked by the guard", String(s.blocked));
  fact("Checkpoints", `${s.signed_checkpoints} signed of ${s.checkpoints}, sealed through receipt ${s.sealed_through}`
    + (s.unsealed_tail ? `, ${s.unsealed_tail} unsealed after that` : ""));
  fact("Signer key", code(signerText),
    keyInput ? null : el("div", { class: "muted small" }, "Confirm this key with the session's owner through a separate channel."));
  if (r.manifest_signer && !s.signers.includes(r.manifest_signer)) fact("Manifest signed by", code(r.manifest_signer));
  fact("Model (self-reported)", s.models.length ? s.models.join(", ") : "not recorded");
  fact("Signature check", `Ed25519 via ${backend}`);
  resultEl.append(el("h2", {}, "Summary"), dl);

  const ul = el("ul", { class: "checks" });
  for (const c of r.checks) {
    const state = c.skipped ? "skip" : c.ok ? "pass" : "failed";
    const label = c.skipped ? "n/a" : c.ok ? "pass" : "fail";
    const li = el("li", { class: state },
      el("span", { class: "tag" }, label),
      el("span", { class: "what" }, c.label,
        c.notes.length ? el("span", { class: "muted small" }, ` (${c.notes.join("; ")})`) : null));
    if (c.errors.length) li.append(el("ul", { class: "errs" }, c.errors.map((e) => el("li", {}, code(e)))));
    ul.append(li);
  }
  resultEl.append(el("h2", {}, "Checks"), ul);

  if (r.destructive.length) {
    const dul = el("ul", { class: "events" });
    for (const d of r.destructive) {
      if (d.decision === "blocked") {
        dul.append(el("li", { class: "deny" },
          el("strong", {}, "Blocked"), ` receipt ${d.seq} at ${d.ts}: ${d.tool} matched rule `, code(d.rule)));
      } else {
        const pc = d.precondition || {};
        const li = el("li", { class: "allow" },
          el("strong", {}, "Allowed under a signed safety check"), ` receipt ${d.seq} at ${d.ts}: rule `, code(d.rule));
        if (pc.missing) {
          li.append(el("div", { class: "small" }, "Precondition ", code(pc.hash), " is not in this pack."));
        } else {
          li.append(el("div", { class: "small" },
            pc.check ? ["check ", code(pc.check)] : ["manual reason: ", pc.manual_reason ?? "none"],
            " · scope ", code(pc.scope), ` · signed ${pc.created} · expires ${pc.expires}`,
            pc.intact ? "" : " · NOT INTACT"));
        }
        dul.append(li);
      }
    }
    resultEl.append(el("h2", {}, "Destructive actions"), dul);
  }

  const aul = el("ul", { class: "events" });
  if (!r.anchors.length) aul.append(el("li", {}, "No independent timestamps in this pack."));
  for (const a of r.anchors) {
    aul.append(el("li", { class: a.linked ? "allow" : "deny" },
      `Checkpoint receipt ${a.seq}: timestamp authority time `, el("strong", {}, a.gen_time ?? "unknown"),
      a.linked ? " (matches the log's checkpoint)" : " (does NOT match the log)",
      a.tsa ? el("span", { class: "muted small" }, ` · ${a.tsa}`) : null));
  }
  resultEl.append(
    el("h2", {}, "Independent timestamps"), aul,
    el("p", { class: "small muted" },
      "Timestamp signatures: verify with ", code("perathos evidence verify"),
      " (CLI). This page checks that each anchor names a checkpoint in the log, not the RFC 3161 token's signature."),
  );

  if (r.warnings.length) {
    resultEl.append(el("h2", {}, "Notes"), el("ul", {}, r.warnings.map((w) => el("li", {}, w))));
  }
  resultEl.hidden = false;
}

// ---- Wiring -------------------------------------------------------------------
$("file").addEventListener("change", async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  if (f) await loadBuffer(await f.arrayBuffer(), f.name);
  ev.target.value = "";
});

const drop = $("drop");
for (const t of ["dragenter", "dragover"]) {
  drop.addEventListener(t, (ev) => { ev.preventDefault(); drop.classList.add("over"); });
}
for (const t of ["dragleave", "drop"]) {
  drop.addEventListener(t, () => drop.classList.remove("over"));
}
drop.addEventListener("drop", async (ev) => {
  ev.preventDefault();
  const f = ev.dataTransfer && ev.dataTransfer.files[0];
  if (f) await loadBuffer(await f.arrayBuffer(), f.name);
});
// Stop a file dropped next to the target from navigating away.
window.addEventListener("dragover", (ev) => ev.preventDefault());
window.addEventListener("drop", (ev) => ev.preventDefault());

$("sample").addEventListener("click", async () => {
  setStatus("Fetching the sample pack ...");
  try {
    const resp = await fetch(SAMPLE_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    await loadBuffer(await resp.arrayBuffer(), "sample-evidence-pack.zip");
  } catch (e) {
    setStatus(`Could not fetch the sample: ${e.message || e}`, true);
  }
});

let keyTimer = null;
keyEl.addEventListener("input", () => {
  clearTimeout(keyTimer);
  keyTimer = setTimeout(run, 250);
});
