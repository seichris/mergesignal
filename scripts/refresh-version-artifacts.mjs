import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

const root = resolve(import.meta.dirname, "..");
const execFile = promisify(execFileCallback);
const digestBytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readJson = async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"));
const digestFile = async (path) => digestBytes(await readFile(resolve(root, path)));
const writeJson = async (path, value) =>
  writeFile(resolve(root, path), `${JSON.stringify(value, null, 2)}\n`);

try {
  await execFile("git", ["cat-file", "-e", "HEAD:contracts/version-registry.json"], { cwd: root });
  throw new Error(
    "Registered version artifacts already have a Git baseline; add new versions instead of refreshing them in place"
  );
} catch (error) {
  if (error?.code !== 128) throw error;
}

const schemaPaths = (await readdir(resolve(root, "contracts")))
  .filter((name) => name.endsWith(".schema.json"))
  .sort()
  .map((name) => `contracts/${name}`);
const schemaArtifacts = Object.fromEntries(await Promise.all(
  [...schemaPaths, "contracts/evidence-types.json", "contracts/reason-codes.json"]
    .map(async (path) => [path, await digestFile(path)])
));
const replayRuntimeArtifactPath =
  "contracts/version-artifacts/bundles/replay-runtime-v1.bundle.mjs";
const replayRuntimeArtifactDigest = await digestFile(replayRuntimeArtifactPath);
const runtimeEnvironmentArtifactPath =
  "contracts/version-artifacts/environments/replay-node22-v1.json";
const runtimeEnvironmentArtifactDigest = await digestFile(runtimeEnvironmentArtifactPath);
const evaluatorMethods = [
  "validateDerivedEvidence",
  "exactDerivationCandidates",
  "calculateDimension",
  "classifyAssessment",
  "expandEligibleDerivations",
  "buildAuthoritativeHistoryEvidenceIds",
  "authoritativeReasonEvidenceIds",
  "buildContextualizationCandidates",
  "classifyPublication",
  "evaluatePublicationFence",
  "requiresCommentRemoval"
];

const registry = await readJson("contracts/version-registry.json");
for (const version of ["engine-v1", "engine-v2"]) {
  const artifactPath = `contracts/version-artifacts/${version}.json`;
  const artifact = await readJson(artifactPath);
  artifact.evaluatorArtifactPath =
    `contracts/version-artifacts/bundles/assessment-${version}.bundle.mjs`;
  artifact.evaluatorArtifactDigest = await digestFile(artifact.evaluatorArtifactPath);
  artifact.evaluatorMethods = evaluatorMethods;
  artifact.replayRuntimeArtifactPath = replayRuntimeArtifactPath;
  artifact.replayRuntimeArtifactDigest = replayRuntimeArtifactDigest;
  artifact.runtimeEnvironmentArtifactPath = runtimeEnvironmentArtifactPath;
  artifact.runtimeEnvironmentArtifactDigest = runtimeEnvironmentArtifactDigest;
  artifact.runtimeArtifacts = {
    [replayRuntimeArtifactPath]: replayRuntimeArtifactDigest,
    [runtimeEnvironmentArtifactPath]: runtimeEnvironmentArtifactDigest
  };
  artifact.schemaArtifacts = schemaArtifacts;
  await writeJson(artifactPath, artifact);
  const registryEntry = registry.entries.find(
    (entry) => entry.kind === "engine" && entry.version === version
  );
  registryEntry.artifactDigest = await digestFile(artifactPath);
}

const modelArtifactPath = "contracts/version-artifacts/model-gpt-5.6-sol.json";
const modelArtifact = await readJson(modelArtifactPath);
modelArtifact.routingPolicyArtifactDigest = await digestFile(modelArtifact.routingPolicyArtifactPath);
modelArtifact.requestSchemaArtifactDigest = await digestFile(modelArtifact.requestSchemaArtifactPath);
modelArtifact.responseSchemaArtifactDigest = await digestFile(modelArtifact.responseSchemaArtifactPath);
await writeJson(modelArtifactPath, modelArtifact);

for (const entry of registry.entries) {
  entry.artifactDigest = await digestFile(entry.artifactPath);
}
await writeJson("contracts/version-registry.json", registry);
console.log(`Refreshed 2 replay engines with ${schemaPaths.length} schemas.`);
