import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import canonicalizePackage from "canonicalize";
import { parseDocument, visit } from "yaml";

export const replayRuntimeContractVersion = "replay-runtime-v1";

export function canonicalizeIJson(value) {
  assertIJsonValue(value);
  const encoded = canonicalizePackage(value);
  if (encoded === undefined) throw new TypeError("Value is not canonical I-JSON");
  return encoded;
}

export function canonicalDigest(value) {
  return createHash("sha256").update(canonicalizeIJson(value), "utf8").digest("hex");
}

export function assertEffectiveInterval(entry, at, assert) {
  const instant = new Date(at);
  assert(Number.isFinite(instant.getTime()), `Invalid replay instant ${at}`);
  assert(
    new Date(entry.effectiveFrom) <= instant &&
      (entry.effectiveUntil === null || instant < new Date(entry.effectiveUntil)),
    `Version ${entry.kind}:${entry.version} is outside its effective interval at ${at}`
  );
  return entry;
}

export function selectEffectiveVersion(entries, kind, at, assert) {
  const candidates = entries.filter(
    (entry) =>
      entry.kind === kind &&
      new Date(entry.effectiveFrom) <= new Date(at) &&
      (entry.effectiveUntil === null || new Date(at) < new Date(entry.effectiveUntil))
  );
  assert(candidates.length === 1, `Replay instant ${at} resolves ${candidates.length} ${kind} versions`);
  return candidates[0];
}

function assertIJsonValue(value, path = "$", seen = new Set()) {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const codeUnit = value.charCodeAt(index);
      if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
        const trailing = value.charCodeAt(index + 1);
        if (!(trailing >= 0xdc00 && trailing <= 0xdfff)) {
          throw new TypeError(`${path} contains an unpaired high surrogate`);
        }
        index += 1;
      } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
        throw new TypeError(`${path} contains an unpaired low surrogate`);
      }
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${path} contains a non-finite number`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`${path} contains an unsafe integer`);
    }
    return;
  }
  if (typeof value !== "object") throw new TypeError(`${path} is not an I-JSON value`);
  if (seen.has(value)) throw new TypeError(`${path} contains an alias or cycle`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertIJsonValue(item, `${path}[${index}]`, seen));
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError(`${path} is not a plain object`);
    }
    for (const [key, item] of Object.entries(value)) {
      assertIJsonValue(key, `${path}.[member-name]`, seen);
      assertIJsonValue(item, `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
}

export function parseMergeSignalYaml(bytes) {
  let source;
  if (typeof bytes === "string") {
    source = bytes;
  } else if (Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) {
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new TypeError("Invalid .github/mergesignal.yml: input is not valid UTF-8");
    }
  } else {
    throw new TypeError("Invalid .github/mergesignal.yml: input must be UTF-8 bytes or text");
  }
  const document = parseDocument(source, {
    schema: "core",
    uniqueKeys: true,
    merge: false,
    maxAliasCount: 0,
    prettyErrors: false,
    strict: true
  });
  if (document.errors.length > 0) {
    throw new TypeError(`Invalid .github/mergesignal.yml: ${document.errors[0].message}`);
  }
  if (document.warnings.length > 0) {
    throw new TypeError(`Unsafe .github/mergesignal.yml: ${document.warnings[0].message}`);
  }
  visit(document, {
    Alias() {
      throw new TypeError("Unsafe .github/mergesignal.yml: aliases are prohibited");
    }
  });
  const value = document.toJS({ maxAliasCount: 0 });
  assertIJsonValue(value);
  canonicalizeIJson(value);
  return value;
}
