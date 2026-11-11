// Perathos evidence-pack verification, shared by the browser page and the Node test.
//
// Re-implements, in plain JavaScript, the checks that `perathos evidence verify`
// runs (perathos/evidence.py, perathos/recorder.py, docs/specs/RECEIPT_V1.md):
// the signed MANIFEST.json, the hash-chained receipt log, checkpoint signatures,
// the head witness, and the anchors' link to the log. RFC 3161 timestamp tokens
// are NOT cryptographically verified here, and Perathos Gate approval receipts
// (approvals/*.json) are NOT checked at all beyond the manifest hash (no
// signature check, no cross-check against the log); use the CLI for both.
//
// Works in browsers and in Node 18+ (both expose WebCrypto as globalThis.crypto).

export const RECEIPT_VERSION = "perathos.receipt/v1";
export const ANCHOR_VERSION = "perathos.anchor/v1";
export const PRECONDITION_VERSION = "perathos.precondition/v1";
export const GENESIS_HASH = "0".repeat(64);

const enc = new TextEncoder();

// --------------------------------------------------------------------------- //
// Canonical JSON: byte-identical to Python's
//   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// for the values Perathos hashes (strings, integers, booleans, null, arrays,
// objects with string keys). Floats are refused rather than risk a silent
// mismatch (Python writes 1.0 where JavaScript writes 1).
// --------------------------------------------------------------------------- //

function compareCodePoints(a, b) {
  // Python sorts str keys by code point; JS default sort uses UTF-16 code
  // units, which differ for characters outside the BMP.
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0);
    const cy = y.value.codePointAt(0);
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

export function canonicalJson(value) {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      // JSON.stringify escapes exactly what Python's ensure_ascii=False
      // escapes: " \ and U+0000..U+001F (\b \f \n \r \t short forms, others
      // as lowercase \u00xx). Non-ASCII is emitted as-is.
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonical JSON: unsupported number ${value} (only safe integers)`);
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
      const keys = Object.keys(value).sort(compareCodePoints);
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`canonical JSON: unsupported type ${typeof value}`);
  }
}

export function canonicalBytes(value) {
  return enc.encode(canonicalJson(value));
}

// --------------------------------------------------------------------------- //
// Hashing and signatures
// --------------------------------------------------------------------------- //

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("WebCrypto is not available (the page must be served over https or localhost)");
  return c.subtle;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await subtle().digest("SHA-256", bytes)));
}

const isHex = (v, len) => typeof v === "string" && v.length === len && /^[0-9a-f]*$/.test(v);

let ed25519Fallback = null;
let webCryptoEd25519 = null; // null = untested, true/false after first try

/** Register a fallback verifier: async (sig, msg, pub) => boolean (e.g. @noble/ed25519 verifyAsync). */
export function setEd25519Fallback(fn) {
  ed25519Fallback = fn;
}

export function ed25519Backend() {
  if (webCryptoEd25519 === true) return "WebCrypto";
  if (webCryptoEd25519 === false && ed25519Fallback) return "@noble/ed25519";
  return "unknown";
}

async function ed25519Verify(pub, sig, msg) {
  if (webCryptoEd25519 !== false) {
    try {
      const key = await subtle().importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
      const ok = await subtle().verify({ name: "Ed25519" }, key, sig, msg);
      webCryptoEd25519 = true;
      return ok;
    } catch (e) {
      // NotSupportedError (or TypeError in some engines) means no Ed25519 in
      // WebCrypto: switch to the fallback. Anything else (e.g. DataError for
      // a key that is not a valid point) means the signature is invalid.
      const unsupported = e && (e.name === "NotSupportedError" || e.name === "TypeError");
      if (webCryptoEd25519 === true || !unsupported) return false;
      webCryptoEd25519 = false;
    }
  }
  if (!ed25519Fallback) throw new Error("Ed25519 is not supported by this browser and no fallback is loaded");
  try {
    return await ed25519Fallback(sig, msg, pub);
  } catch {
    return false;
  }
}

/**
 * Mirrors perathos.signing.verify_signature: Ed25519 over the 32 raw bytes of
 * a hex SHA-256 hash. Returns [ok, errorCode].
 */
export async function verifySignature(hashHex, sig) {
  if (!sig || typeof sig !== "object" || Array.isArray(sig)) return [false, "ERR_MISSING_SIG_FIELD"];
  if (sig.algorithm !== "ed25519") return [false, "ERR_UNSUPPORTED_ALGORITHM"];
  if (!isHex(hashHex, 64)) return [false, "ERR_INVALID_HASH"];
  if (!("verify_key" in sig)) return [false, "ERR_MISSING_SIG_FIELD"];
  if (!isHex(sig.verify_key, 64)) return [false, "ERR_INVALID_VERIFY_KEY"];
  if (!("signature" in sig)) return [false, "ERR_MISSING_SIG_FIELD"];
  if (!isHex(sig.signature, 128)) return [false, "ERR_INVALID_SIGNATURE"];
  const ok = await ed25519Verify(fromHex(sig.verify_key), fromHex(sig.signature), fromHex(hashHex));
  return ok ? [true, ""] : [false, "ERR_BAD_SIGNATURE"];
}

// --------------------------------------------------------------------------- //
// Pack loading helpers
// --------------------------------------------------------------------------- //

/**
 * Normalise zip entry names the way verify_evidence_pack does: reject unsafe
 * paths, and if everything sits in one top-level folder, strip it.
 * `entries` is a Map<string, Uint8Array>; returns a new Map.
 */
export function normalizeEntries(entries) {
  const names = [...entries.keys()].map((n) => n.replace(/\\/g, "/"));
  for (const n of names) {
    if (n.startsWith("/") || /^[A-Za-z]:/.test(n) || n.split("/").includes("..")) {
      throw new Error(`unsafe path in zip: ${n}`);
    }
  }
  const tops = new Set(names.map((n) => (n.includes("/") ? n.split("/")[0] + "/" : n)));
  let prefix = "";
  if (tops.size === 1) {
    const only = [...tops][0];
    if (only.endsWith("/")) prefix = only;
  }
  const out = new Map();
  for (const [name, data] of entries) {
    const n = name.replace(/\\/g, "/");
    out.set(prefix && n.startsWith(prefix) ? n.slice(prefix.length) : n, data);
  }
  return out;
}

function decodeUtf8(bytes) {
  // fatal: invalid UTF-8 is an error, as in Python; ignoreBOM: keep a BOM so
  // it fails JSON parsing, as Python's "utf-8" codec does.
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

function splitLines(text) {
  const lines = text.split(/\r\n|\n|\r/);
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const pyStr = (v) => (v === undefined || v === null ? "None" : String(v));

// --------------------------------------------------------------------------- //
// Verification
// --------------------------------------------------------------------------- //

/**
 * Verify an evidence pack.
 * @param {Map<string, Uint8Array>} files  paths relative to the pack root
 * @param {{expectedKey?: string}} opts
 */
export async function verifyPack(files, opts = {}) {
  const expectedKey = (opts.expectedKey || "").trim().toLowerCase() || null;
  const checks = [];
  const check = (id, label) => {
    const c = { id, label, errors: [], notes: [], skipped: false };
    checks.push(c);
    return c;
  };
  const warnings = [];

  const cManHash = check("manifest_hash", "Manifest hash recomputes");
  const cManSig = check("manifest_sig", "Manifest signature is valid");
  const cFiles = check("files", "Every file is listed and unmodified");
  const cParse = check("parse", "Every receipt parses, with a known version and kind");
  const cSeq = check("seq", "Sequence numbers run 1, 2, 3 ... with no gaps");
  const cChain = check("chain", "Each receipt links to the previous one (prev_hash)");
  const cRHash = check("receipt_hash", "Every receipt hash recomputes");
  const cSid = check("session_id", "One session id throughout");
  const cTime = check("time", "Timestamps never go backwards");
  const cCp = check("checkpoints", "Checkpoints are signed and the signatures verify");
  const cSigner = check("signer", expectedKey ? "Signed by the expected key" : "Signed by the expected key (no key given)");
  const cHead = check("head", "Head witness matches the log (no truncation)");
  const cAnch = check("anchors", "Timestamp anchors point at checkpoints in the log");
  const cPre = check("preconditions", "Safety checks (preconditions) are in the pack, intact and signed");

  // ---- Manifest ----------------------------------------------------------
  let manifest = null;
  if (!files.has("MANIFEST.json")) {
    cManHash.errors.push("ERR_MISSING_FILE: MANIFEST.json");
    cManSig.skipped = true;
    cFiles.skipped = true;
  } else {
    try {
      manifest = JSON.parse(decodeUtf8(files.get("MANIFEST.json")));
    } catch {
      manifest = null;
    }
    if (!isObj(manifest)) {
      cManHash.errors.push("ERR_MANIFEST_MALFORMED: MANIFEST.json is not a JSON object");
      cManSig.skipped = true;
      cFiles.skipped = true;
      manifest = null;
    }
  }
  if (manifest) {
    const body = {};
    for (const k of Object.keys(manifest)) if (k !== "manifest_hash" && k !== "signature") body[k] = manifest[k];
    let recomputed = null;
    try {
      recomputed = await sha256Hex(canonicalBytes(body));
    } catch {
      recomputed = null;
    }
    if (recomputed !== manifest.manifest_hash) cManHash.errors.push("ERR_MANIFEST_HASH: manifest was modified");

    const sig = manifest.signature;
    if (sig === undefined || sig === null) {
      cManSig.errors.push("ERR_MANIFEST_UNSIGNED: the pack manifest is not signed");
    } else {
      const [ok, err] = await verifySignature(pyStr(manifest.manifest_hash), sig);
      if (!ok) cManSig.errors.push(`${err}: manifest signature`);
      else {
        cManSig.notes.push(`key ${sig.verify_key}`);
        if (expectedKey && sig.verify_key !== expectedKey) {
          cSigner.errors.push("ERR_UNEXPECTED_SIGNER: manifest signed by a different key");
        }
      }
    }

    const listed = isObj(manifest.files) ? manifest.files : {};
    for (const [name, digest] of Object.entries(listed)) {
      if (!files.has(name)) cFiles.errors.push(`ERR_MISSING_FILE: ${name}`);
      else if ((await sha256Hex(files.get(name))) !== digest) cFiles.errors.push(`ERR_FILE_MODIFIED: ${name}`);
    }
    const extras = [...files.keys()].filter((n) => n !== "MANIFEST.json" && !(n in listed)).sort();
    for (const n of extras) cFiles.errors.push(`ERR_UNLISTED_FILE: ${n}`);
    cFiles.notes.push(`${Object.keys(listed).length} file(s) listed`);
  }

  // ---- Session log ---------------------------------------------------------
  const stats = {
    session_id: null, receipts: 0, tool_calls: 0, blocked: 0, checkpoints: 0, signed_checkpoints: 0,
    sealed_through: 0, unsealed_tail: 0, signers: [], models: [], tools: {}, first_ts: null, last_ts: null,
  };
  const receipts = [];
  const checkpointIndex = new Map();
  let logText = null;
  if (!files.has("session.jsonl")) {
    cParse.errors.push("ERR_UNREADABLE: session.jsonl is missing");
  } else {
    try {
      logText = decodeUtf8(files.get("session.jsonl"));
    } catch (e) {
      cParse.errors.push(`ERR_UNREADABLE: session.jsonl is not valid UTF-8`);
    }
  }

  if (logText !== null) {
    let prev = GENESIS_HASH;
    let expectedSeq = 1;
    let lastTs = "";
    const openPre = new Map();
    const lines = splitLines(logText);
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const lineno = i + 1;
      if (!raw.trim()) continue;
      const rec = parseJson(raw);
      if (!isObj(rec)) {
        cParse.errors.push(`ERR_MALFORMED at line ${lineno}: not a JSON object`);
        prev = await sha256Hex(enc.encode(raw));
        expectedSeq += 1;
        continue;
      }
      stats.receipts += 1;
      receipts.push(rec);
      const seq = rec.seq;
      const where = `seq ${pyStr(seq)} (line ${lineno})`;

      if (rec.v !== RECEIPT_VERSION) cParse.errors.push(`ERR_VERSION at ${where}: ${JSON.stringify(rec.v ?? null)}`);
      if (!(Number.isInteger(seq) && seq === expectedSeq)) {
        cSeq.errors.push(`ERR_SEQ at ${where}: expected ${expectedSeq} (a receipt is missing, duplicated or reordered)`);
      }
      if (rec.prev_hash !== prev) cChain.errors.push(`ERR_CHAIN at ${where}: prev_hash does not match the previous receipt`);
      const body = {};
      for (const k of Object.keys(rec)) if (k !== "receipt_hash" && k !== "signature") body[k] = rec[k];
      let recomputed = null;
      try {
        recomputed = await sha256Hex(canonicalBytes(body));
      } catch {
        recomputed = null;
      }
      if (recomputed !== rec.receipt_hash) cRHash.errors.push(`ERR_RECEIPT_HASH at ${where}: receipt was modified`);

      const sid = rec.session_id;
      if (stats.session_id === null) stats.session_id = sid ?? null;
      else if (sid !== stats.session_id) {
        cSid.errors.push(`ERR_SESSION_ID at ${where}: ${JSON.stringify(sid ?? null)} != ${JSON.stringify(stats.session_id)}`);
      }

      const ts = rec.ts ? String(rec.ts) : "";
      if (lastTs && ts < lastTs) cTime.errors.push(`ERR_TIME at ${where}: timestamp goes backwards`);
      if (ts > lastTs) lastTs = ts;
      stats.first_ts = stats.first_ts || ts;
      stats.last_ts = ts;

      const kind = rec.kind;
      if (kind === "pre") {
        stats.tool_calls += 1;
        const tool = rec.tool ? String(rec.tool) : "";
        stats.tools[tool] = (stats.tools[tool] || 0) + 1;
        const guard = rec.guard;
        if (isObj(guard) && guard.decision === "deny") stats.blocked += 1;
        else if (rec.tool_use_id) openPre.set(String(rec.tool_use_id), tool);
      } else if (kind === "post") {
        const tuid = rec.tool_use_id;
        if (tuid && !openPre.has(String(tuid))) warnings.push(`result without a matching call at ${where}`);
        openPre.delete(String(tuid));
      } else if (kind === "checkpoint") {
        stats.checkpoints += 1;
        if (Number.isInteger(seq)) {
          checkpointIndex.set(seq, rec);
          stats.sealed_through = seq;
        }
        if (typeof rec.model === "string" && !stats.models.includes(rec.model)) stats.models.push(rec.model);
        const sig = rec.signature;
        if (sig === undefined || sig === null) {
          cCp.errors.push(`ERR_UNSIGNED at ${where}: checkpoint has no signature`);
        } else if (!isObj(sig)) {
          cCp.errors.push(`ERR_BAD_SIGNATURE at ${where}`);
        } else {
          const [ok, err] = await verifySignature(pyStr(rec.receipt_hash), sig);
          if (!ok) cCp.errors.push(`${err} at ${where}`);
          else {
            const vk = sig.verify_key;
            if (rec.signer !== vk) cCp.errors.push(`ERR_SIGNER_MISMATCH at ${where}: signature key differs from the bound signer`);
            if (expectedKey && vk !== expectedKey) cSigner.errors.push(`ERR_UNEXPECTED_SIGNER at ${where}`);
            if (!stats.signers.includes(vk)) stats.signers.push(vk);
            stats.signed_checkpoints += 1;
          }
        }
      } else {
        cParse.errors.push(`ERR_KIND at ${where}: unknown kind ${JSON.stringify(kind ?? null)}`);
      }

      prev = pyStr(rec.receipt_hash);
      expectedSeq = Number.isInteger(seq) ? seq + 1 : expectedSeq + 1;
    }

    if (stats.receipts === 0) cParse.errors.push("ERR_EMPTY: no receipts");
    else if (stats.signed_checkpoints === 0) cCp.errors.push("ERR_UNSIGNED: no signed checkpoint seals this log");
    stats.unsealed_tail = Math.max(0, expectedSeq - 1 - stats.sealed_through);
    if (stats.unsealed_tail) warnings.push(`${stats.unsealed_tail} receipt(s) after the last checkpoint are not sealed yet`);
    if (openPre.size) warnings.push(`${openPre.size} tool call(s) have no result receipt (failed, denied or interrupted)`);
    if (stats.signers.length > 1) warnings.push(`${stats.signers.length} different keys signed checkpoints in this log`);
    if (stats.signed_checkpoints) cCp.notes.push(`${stats.signed_checkpoints} signed checkpoint(s), sealed through seq ${stats.sealed_through}`);
  } else {
    for (const c of [cSeq, cChain, cRHash, cSid, cTime, cCp]) c.skipped = true;
  }
  if (!expectedKey) cSigner.skipped = true;

  // ---- Head witness ------------------------------------------------------
  if (!files.has("session.head.json")) {
    cHead.skipped = true;
    cHead.notes.push("no head witness in this pack");
  } else {
    let head;
    try {
      head = JSON.parse(decodeUtf8(files.get("session.head.json")));
    } catch {
      head = undefined;
    }
    const hseq = isObj(head) ? head.seq : undefined;
    if (!isObj(head) || !Number.isInteger(hseq)) {
      warnings.push("head witness file is unreadable");
      cHead.skipped = true;
    } else if (hseq > stats.sealed_through) {
      cHead.errors.push(`ERR_TRUNCATED: head witness records seq ${hseq}, log sealed through ${stats.sealed_through}`);
    } else {
      const cp = checkpointIndex.get(hseq);
      if (!cp || cp.receipt_hash !== head.receipt_hash) {
        cHead.errors.push(`ERR_HEAD_MISMATCH: checkpoint seq ${hseq} differs from the head witness`);
      } else {
        cHead.notes.push(`witnesses checkpoint seq ${hseq}`);
      }
    }
  }

  // ---- Anchors (link only; tokens are not verified here) -----------------
  const anchors = [];
  if (!files.has("anchors.jsonl")) {
    cAnch.skipped = true;
    cAnch.notes.push("no timestamp anchors in this pack");
  } else {
    let text = null;
    try {
      text = decodeUtf8(files.get("anchors.jsonl"));
    } catch {
      cAnch.errors.push("ERR_ANCHOR_MALFORMED: anchors.jsonl is not valid UTF-8");
    }
    for (const line of text === null ? [] : splitLines(text)) {
      if (!line.trim()) continue;
      const a = parseJson(line);
      if (!isObj(a) || a.v !== ANCHOR_VERSION) {
        cAnch.errors.push("ERR_ANCHOR_MALFORMED: unreadable anchor record");
        continue;
      }
      const { seq, receipt_hash: h } = a;
      const cp = Number.isInteger(seq) ? checkpointIndex.get(seq) : undefined;
      const entry = { seq, gen_time: a.gen_time ?? null, tsa: a.tsa ?? null, receipt_hash: h, linked: false };
      anchors.push(entry);
      if (!cp || cp.receipt_hash !== h) {
        if (Number.isInteger(seq) && seq > stats.sealed_through) {
          cAnch.errors.push(
            `ERR_TRUNCATED: an independent timestamp proves checkpoint seq ${seq} existed at ` +
              `${pyStr(a.gen_time)}, but the log is sealed only through seq ${stats.sealed_through}`,
          );
        } else {
          cAnch.errors.push(`ERR_ANCHOR_MISMATCH: anchor for seq ${pyStr(seq)} does not match the log's checkpoint`);
        }
        continue;
      }
      if (typeof a.token !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(a.token) || a.token.length % 4 !== 0) {
        cAnch.errors.push(`ERR_ANCHOR_MALFORMED at seq ${seq}`);
        continue;
      }
      entry.linked = true;
    }
    if (anchors.length) cAnch.notes.push(`${anchors.filter((a) => a.linked).length} of ${anchors.length} anchor(s) match a checkpoint`);
  }

  // ---- Preconditions + destructive-action summary ------------------------
  const preconditions = new Map(); // precondition_hash -> {pc, ok}
  const pcFiles = [...files.keys()].filter((n) => n.startsWith("preconditions/") && n.endsWith(".json"));
  for (const name of pcFiles) {
    let pc;
    try {
      pc = JSON.parse(decodeUtf8(files.get(name)));
    } catch {
      pc = undefined;
    }
    if (!isObj(pc)) {
      cPre.errors.push(`ERR_PRECONDITION_MALFORMED: ${name}`);
      continue;
    }
    const body = {};
    for (const k of Object.keys(pc)) if (k !== "precondition_hash" && k !== "signature") body[k] = pc[k];
    let h = null;
    try {
      h = await sha256Hex(canonicalBytes(body));
    } catch {
      h = null;
    }
    let ok = true;
    if (h !== pc.precondition_hash) {
      cPre.errors.push(`ERR_PRECONDITION_HASH: ${name} was modified`);
      ok = false;
    } else {
      const [sok, err] = await verifySignature(pyStr(pc.precondition_hash), pc.signature);
      if (!sok) {
        cPre.errors.push(`${err}: ${name}`);
        ok = false;
      } else if (pc.signer !== pc.signature.verify_key) {
        cPre.errors.push(`ERR_SIGNER_MISMATCH: ${name}`);
        ok = false;
      } else if (expectedKey && pc.signature.verify_key !== expectedKey) {
        cSigner.errors.push(`ERR_UNEXPECTED_SIGNER: ${name}`);
      }
    }
    preconditions.set(pyStr(pc.precondition_hash), { pc, ok });
  }

  const destructive = [];
  for (const r of receipts) {
    const g = r.guard;
    if (r.kind !== "pre" || !isObj(g)) continue;
    const item = { seq: r.seq, ts: r.ts, tool: r.tool, rule: g.rule ?? null, decision: g.decision === "deny" ? "blocked" : "allowed" };
    if (item.decision === "allowed") {
      const found = preconditions.get(pyStr(g.precondition));
      if (found) {
        const pc = found.pc;
        item.precondition = {
          id: pc.id, scope: pc.scope, check: pc.check, manual_reason: pc.manual_reason,
          created: pc.created, expires: pc.expires, intact: found.ok,
        };
      } else {
        item.precondition = { hash: g.precondition ?? null, missing: true };
        if (g.precondition) {
          cPre.errors.push(
            `ERR_PRECONDITION_MISSING: receipt ${pyStr(r.seq)} cites precondition ` +
              `${pyStr(g.precondition).slice(0, 16)}..., which is not in the pack`,
          );
        }
      }
    }
    destructive.push(item);
  }
  if (!pcFiles.length && !cPre.errors.length) {
    cPre.skipped = true;
    cPre.notes.push("no preconditions in this pack");
  } else if (!cPre.errors.length) {
    cPre.notes.push(`${pcFiles.length} precondition(s) checked`);
  }

  // ---- Result ------------------------------------------------------------
  const errors = checks.flatMap((c) => c.errors);
  for (const c of checks) c.ok = c.errors.length === 0;
  const lastAnchored = anchors.filter((a) => a.linked).sort((a, b) => b.seq - a.seq)[0];
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    checks,
    stats: {
      ...stats,
      anchors: anchors.length,
      anchors_linked: anchors.filter((a) => a.linked).length,
      anchored_through: lastAnchored ? lastAnchored.seq : 0,
      anchored_time: lastAnchored ? lastAnchored.gen_time : null,
    },
    anchors,
    destructive,
    manifest_signer: manifest && isObj(manifest.signature) ? manifest.signature.verify_key : null,
    ed25519: ed25519Backend(),
  };
}
