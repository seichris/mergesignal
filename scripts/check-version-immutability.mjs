import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const execFile = promisify(execFileCallback);
const root = resolve(import.meta.dirname, "..");
const registryPath = "contracts/version-registry.json";
const immutableFields = ["artifactPath", "artifactDigest", "effectiveFrom"];

function entryKey(entry) {
  return `${entry.kind}:${entry.version}`;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSameRegisteredVersion(older, newer, context) {
  const key = entryKey(older);
  for (const field of immutableFields) {
    if (newer[field] !== older[field]) {
      throw new Error(`Registered version changed immutable ${field}: ${key} (${context})`);
    }
  }
  if (older.status === "retired" && newer.status !== "retired") {
    throw new Error(`Retired version was reactivated: ${key} (${context})`);
  }
  if (older.effectiveUntil !== null && newer.effectiveUntil !== older.effectiveUntil) {
    throw new Error(`Closed effective interval changed: ${key} (${context})`);
  }
}

function assertRegistryTransition(olderRegistry, newerRegistry, context) {
  if (olderRegistry && !newerRegistry) {
    throw new Error(`Version registry was removed (${context})`);
  }
  if (!olderRegistry) return;
  const newerByKey = new Map(newerRegistry.entries.map((entry) => [entryKey(entry), entry]));
  if (newerByKey.size !== newerRegistry.entries.length) {
    throw new Error(`Duplicate registered kind/version in ${context}`);
  }
  for (const older of olderRegistry.entries) {
    const newer = newerByKey.get(entryKey(older));
    if (!newer) throw new Error(`Registered version was removed: ${entryKey(older)} (${context})`);
    assertSameRegisteredVersion(older, newer, context);
  }
}

async function gitBytes(commit, path) {
  try {
    const { stdout } = await execFile("git", ["show", `${commit}:${path}`], {
      cwd: root,
      encoding: "buffer",
      maxBuffer: 32 * 1024 * 1024
    });
    return Buffer.from(stdout);
  } catch (error) {
    if (error?.code === 128) return null;
    throw error;
  }
}

async function verifyArtifactBytes(registry, readBytes, context) {
  if (!registry) return;
  const keys = new Set(registry.entries.map(entryKey));
  if (keys.size !== registry.entries.length) {
    throw new Error(`Duplicate registered kind/version in ${context}`);
  }

  for (const entry of registry.entries) {
    const bytes = await readBytes(entry.artifactPath);
    if (!bytes) throw new Error(`Registered artifact is absent: ${entryKey(entry)} (${context})`);
    if (sha256(bytes) !== entry.artifactDigest) {
      throw new Error(`Registered artifact bytes changed in place: ${entryKey(entry)} (${context})`);
    }

    let artifact;
    try {
      artifact = JSON.parse(bytes.toString("utf8"));
    } catch {
      continue;
    }

    const nestedArtifacts = [];
    const collectDirectArtifactBindings = (value, objectPath = "$") => {
      if (Array.isArray(value)) {
        value.forEach((item, index) => collectDirectArtifactBindings(item, `${objectPath}[${index}]`));
        return;
      }
      if (value === null || typeof value !== "object") return;
      for (const [key, member] of Object.entries(value)) {
        if ((key === "artifactPath" || key.endsWith("ArtifactPath")) && typeof member === "string") {
          const digestKey = key === "artifactPath"
            ? "artifactDigest"
            : `${key.slice(0, -"Path".length)}Digest`;
          const digest = value[digestKey];
          if (typeof digest !== "string") {
            throw new Error(`Artifact path lacks sibling digest at ${objectPath}.${key} (${context})`);
          }
          nestedArtifacts.push([member, digest]);
        }
        collectDirectArtifactBindings(member, `${objectPath}.${key}`);
      }
    };
    collectDirectArtifactBindings(artifact);
    for (const memberName of [
      "executableArtifacts",
      "schemaArtifacts",
      "runtimeArtifacts",
      "artifacts"
    ]) {
      for (const [path, digest] of Object.entries(artifact[memberName] ?? {})) {
        nestedArtifacts.push([path, digest]);
      }
    }
    for (const [path, expectedDigest] of nestedArtifacts) {
      const memberBytes = await readBytes(path);
      if (!memberBytes || sha256(memberBytes) !== expectedDigest) {
        throw new Error(`Registered nested artifact bytes changed in place: ${entryKey(entry)} -> ${path} (${context})`);
      }
    }
  }
}

async function reachableCommitSnapshots(repoRoot = root) {
  const { stdout: shallow } = await execFile("git", ["rev-parse", "--is-shallow-repository"], { cwd: repoRoot });
  if (shallow.trim() !== "false") {
    throw new Error("Version immutability verification requires a complete, non-shallow Git history");
  }
  await execFile("git", ["fsck", "--connectivity-only", "--no-dangling"], { cwd: repoRoot });
  const { stdout } = await execFile("git", ["rev-list", "--topo-order", "--reverse", "--all"], { cwd: repoRoot });
  const commits = stdout.trim().split(/\s+/).filter(Boolean);
  const snapshots = new Map();
  for (const commit of commits) {
    const registryBytes = await gitBytesAt(repoRoot, commit, registryPath);
    const { stdout: parentLine } = await execFile("git", ["rev-list", "--parents", "-n", "1", commit], { cwd: repoRoot });
    const [, ...parents] = parentLine.trim().split(/\s+/);
    snapshots.set(commit, {
      commit,
      parents,
      registry: registryBytes ? JSON.parse(registryBytes.toString("utf8")) : null
    });
  }
  return snapshots;
}

async function gitBytesAt(repoRoot, commit, path) {
  try {
    const { stdout } = await execFile("git", ["show", `${commit}:${path}`], {
      cwd: repoRoot,
      encoding: "buffer",
      maxBuffer: 32 * 1024 * 1024
    });
    return Buffer.from(stdout);
  } catch (error) {
    if (error?.code === 128) return null;
    throw error;
  }
}

function assertGlobalVersionIdentity(snapshots) {
  const globallyRegistered = new Map();
  for (const snapshot of snapshots.values()) {
    for (const entry of snapshot.registry?.entries ?? []) {
      const key = entryKey(entry);
      const previous = globallyRegistered.get(key);
      if (previous) {
        assertSameRegisteredVersion(previous.entry, entry, `${previous.commit} <> ${snapshot.commit}`);
        assertSameRegisteredVersion(entry, previous.entry, `${snapshot.commit} <> ${previous.commit}`);
      } else {
        globallyRegistered.set(key, { entry, commit: snapshot.commit });
      }
    }
  }
}

async function assertHistoricalDAG(repoRoot, snapshots) {
  assertGlobalVersionIdentity(snapshots);
  for (const snapshot of snapshots.values()) {
    await verifyArtifactBytes(
      snapshot.registry,
      (path) => gitBytesAt(repoRoot, snapshot.commit, path),
      snapshot.commit
    );
    for (const parent of snapshot.parents) {
      const parentSnapshot = snapshots.get(parent);
      if (parentSnapshot) {
        assertRegistryTransition(parentSnapshot.registry, snapshot.registry, `${parent} -> ${snapshot.commit}`);
      }
    }
  }
}

async function runBuiltInRegressions() {
  const base = {
    entries: [{ kind: "features", version: "features-v1", artifactPath: "a.json", artifactDigest: "a".repeat(64), effectiveFrom: "2026-01-01T00:00:00Z", effectiveUntil: null, status: "active" }]
  };
  const rewrite = structuredClone(base);
  rewrite.entries[0].artifactDigest = "b".repeat(64);
  let rewriteRejected = false;
  try {
    assertRegistryTransition(base, rewrite, "built-in rewrite regression");
  } catch {
    rewriteRejected = true;
  }
  if (!rewriteRejected) throw new Error("Version immutability guard failed to reject an in-place rewrite");

  // A diamond is valid when each branch adds a different version and the merge
  // retains both. Comparing actual parent edges accepts it; linearizing the two
  // sibling commits would incorrectly report a removal.
  const branchA = structuredClone(base);
  branchA.entries.push({ ...base.entries[0], version: "features-v2", artifactPath: "b.json", artifactDigest: "b".repeat(64) });
  const branchB = structuredClone(base);
  branchB.entries.push({ ...base.entries[0], kind: "policy", version: "policy-v1", artifactPath: "c.json", artifactDigest: "c".repeat(64) });
  const merge = { entries: [...branchA.entries, branchB.entries.at(-1)] };
  assertRegistryTransition(base, branchA, "built-in diamond base -> branch A");
  assertRegistryTransition(base, branchB, "built-in diamond base -> branch B");
  assertRegistryTransition(branchA, merge, "built-in diamond branch A -> merge");
  assertRegistryTransition(branchB, merge, "built-in diamond branch B -> merge");

  const divergentSiblingA = { entries: [{ ...base.entries[0], version: "features-v3", artifactDigest: "c".repeat(64) }] };
  const divergentSiblingB = { entries: [{ ...base.entries[0], version: "features-v3", artifactDigest: "d".repeat(64) }] };
  let divergentSiblingRejected = false;
  try {
    assertGlobalVersionIdentity(new Map([
      ["branch-a", { commit: "branch-a", registry: divergentSiblingA }],
      ["branch-b", { commit: "branch-b", registry: divergentSiblingB }]
    ]));
  } catch {
    divergentSiblingRejected = true;
  }
  if (!divergentSiblingRejected) {
    throw new Error("Version immutability guard accepted divergent sibling registrations for the same version");
  }

  const nestedArtifact = {
    artifacts: { "contracts/member.json": sha256(Buffer.from("member-v1")) }
  };
  let nestedRewriteRejected = false;
  try {
    await verifyArtifactBytes(
      { entries: [{ ...base.entries[0], artifactDigest: sha256(Buffer.from(JSON.stringify(nestedArtifact))) }] },
      async (path) => path === "a.json" ? Buffer.from(JSON.stringify(nestedArtifact)) : Buffer.from("member-v2"),
      "built-in nested-member rewrite regression"
    );
  } catch {
    nestedRewriteRejected = true;
  }
  if (!nestedRewriteRejected) throw new Error("Version immutability guard failed to reject a nested artifact rewrite");

  const directBindingArtifact = {
    dependency: {
      routingPolicyArtifactPath: "contracts/routing.json",
      routingPolicyArtifactDigest: sha256(Buffer.from("routing-v1"))
    }
  };
  let directBindingRewriteRejected = false;
  try {
    await verifyArtifactBytes(
      { entries: [{ ...base.entries[0], artifactDigest: sha256(Buffer.from(JSON.stringify(directBindingArtifact))) }] },
      async (path) => path === "a.json" ? Buffer.from(JSON.stringify(directBindingArtifact)) : Buffer.from("routing-v2"),
      "built-in direct-artifact binding rewrite regression"
    );
  } catch {
    directBindingRewriteRejected = true;
  }
  if (!directBindingRewriteRejected) {
    throw new Error("Version immutability guard failed to reject a direct nested artifact binding rewrite");
  }

  const genericDirectBindingArtifact = {
    dependency: {
      artifactPath: "contracts/generic.json",
      artifactDigest: sha256(Buffer.from("generic-v1"))
    }
  };
  let genericDirectBindingRewriteRejected = false;
  try {
    await verifyArtifactBytes(
      { entries: [{ ...base.entries[0], artifactDigest: sha256(Buffer.from(JSON.stringify(genericDirectBindingArtifact))) }] },
      async (path) => path === "a.json" ? Buffer.from(JSON.stringify(genericDirectBindingArtifact)) : Buffer.from("generic-v2"),
      "built-in generic artifact binding rewrite regression"
    );
  } catch {
    genericDirectBindingRewriteRejected = true;
  }
  if (!genericDirectBindingRewriteRejected) {
    throw new Error("Version immutability guard failed to reject a generic nested artifact binding rewrite");
  }

  const tempRoot = await mkdtemp(resolve(tmpdir(), "mergesignal-version-history-"));
  try {
    await mkdir(resolve(tempRoot, "contracts"), { recursive: true });
    await execFile("git", ["init", "--quiet"], { cwd: tempRoot });
    await execFile("git", ["config", "user.email", "contracts@mergesignal.invalid"], { cwd: tempRoot });
    await execFile("git", ["config", "user.name", "MergeSignal contract test"], { cwd: tempRoot });
    await writeFile(resolve(tempRoot, "contracts/a.json"), "artifact-v1");
    await writeFile(resolve(tempRoot, registryPath), JSON.stringify({
      schemaVersion: "1.0.0",
      version: "1.0.0",
      entries: [{ ...base.entries[0], artifactDigest: sha256(Buffer.from("artifact-v1")) }]
    }));
    await execFile("git", ["add", "."], { cwd: tempRoot });
    await execFile("git", ["commit", "--quiet", "-m", "register"], { cwd: tempRoot });
    await rm(resolve(tempRoot, registryPath));
    await execFile("git", ["add", "-u"], { cwd: tempRoot });
    await execFile("git", ["commit", "--quiet", "-m", "delete registry"], { cwd: tempRoot });
    await writeFile(resolve(tempRoot, registryPath), JSON.stringify({
      schemaVersion: "1.0.0",
      version: "1.0.0",
      entries: [{ ...base.entries[0], artifactDigest: sha256(Buffer.from("artifact-v1")) }]
    }));
    await execFile("git", ["add", "."], { cwd: tempRoot });
    await execFile("git", ["commit", "--quiet", "-m", "restore registry"], { cwd: tempRoot });
    let deletionRejected = false;
    try {
      const snapshots = await reachableCommitSnapshots(tempRoot);
      await assertHistoricalDAG(tempRoot, snapshots);
    } catch {
      deletionRejected = true;
    }
    if (!deletionRejected) throw new Error("Version immutability guard accepted registry deletion and restoration");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

await runBuiltInRegressions();

const current = JSON.parse(await readFile(resolve(root, registryPath), "utf8"));
await verifyArtifactBytes(current, async (path) => readFile(resolve(root, path)), "working tree");

const history = await reachableCommitSnapshots();
await assertHistoricalDAG(root, history);

let headSnapshot = null;
try {
  const { stdout } = await execFile("git", ["rev-parse", "HEAD"], { cwd: root });
  headSnapshot = history.get(stdout.trim()) ?? null;
} catch {
  // A repository without a commit has no historical baseline yet.
}
if (headSnapshot?.registry) {
  assertRegistryTransition(headSnapshot.registry, current, `${headSnapshot.commit} -> working tree`);
}

console.log(
  history.size === 0
    ? `Version immutability valid current=${current.entries.length}; first commit will establish history baseline`
    : `Version immutability valid reachableSnapshots=${history.size} current=${current.entries.length}`
);
