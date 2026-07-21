import { readFile, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";

import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const checkMode = process.argv.includes("--check");
const execFile = promisify(execFileCallback);
let registryHasGitBaseline = false;
try {
  await execFile("git", ["cat-file", "-e", "HEAD:contracts/version-registry.json"], { cwd: root });
  registryHasGitBaseline = true;
} catch (error) {
  if (error?.code !== 128) throw error;
}
if (registryHasGitBaseline && !checkMode) {
  throw new Error(
    "Registered replay outputs are immutable after the Git baseline; use the new-version publication workflow instead of overwriting them"
  );
}
const entries = [
  [
    "contracts/version-artifacts/runtime/replay-runtime-v1.mjs",
    "contracts/version-artifacts/bundles/replay-runtime-v1.bundle.mjs"
  ],
  [
    "contracts/version-artifacts/evaluators/assessment-engine-v1.mjs",
    "contracts/version-artifacts/bundles/assessment-engine-v1.bundle.mjs"
  ],
  [
    "contracts/version-artifacts/evaluators/assessment-engine-v2.mjs",
    "contracts/version-artifacts/bundles/assessment-engine-v2.bundle.mjs"
  ]
];

for (const [entryPoint, outfile] of entries) {
  const result = await build({
    absWorkingDir: root,
    entryPoints: [entryPoint],
    bundle: true,
    write: false,
    platform: "node",
    format: "esm",
    target: "node22",
    banner: {
      js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);"
    },
    charset: "utf8",
    legalComments: "none",
    sourcemap: false,
    treeShaking: true
  });
  const bytes = result.outputFiles[0].contents;
  const absoluteOutfile = resolve(root, outfile);
  if (checkMode) {
    let existing;
    try {
      existing = await readFile(absoluteOutfile);
    } catch {
      throw new Error(`Missing generated replay artifact: ${outfile}`);
    }
    if (!existing.equals(bytes)) {
      throw new Error(`Generated replay artifact is stale: ${outfile}`);
    }
  } else {
    await writeFile(absoluteOutfile, bytes);
  }
}

console.log(`${checkMode ? "Verified" : "Built"} ${entries.length} content-addressed replay bundles.`);
