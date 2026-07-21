import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstat, readFile, readlink } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = execFileSync(
  "git",
  ["ls-files", "-co", "--exclude-standard", "-z"],
  { cwd: root, encoding: "buffer" }
);
const paths = output
  .toString("utf8")
  .split("\0")
  .filter(Boolean)
  .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));

if (new Set(paths).size !== paths.length) {
  throw new Error("Review snapshot inventory contains duplicate paths");
}

const inventoryHash = createHash("sha256");
function inventoryEntryHash(entry) {
  return createHash("sha256").update(JSON.stringify(entry), "utf8").digest("hex");
}

function normalizedRegularFileMode(mode) {
  return (mode & 0o111) !== 0 ? "100755" : "100644";
}

if (
  normalizedRegularFileMode(0o100600) !== "100644" ||
  normalizedRegularFileMode(0o100644) !== "100644" ||
  normalizedRegularFileMode(0o100664) !== "100644" ||
  normalizedRegularFileMode(0o100700) !== "100755" ||
  normalizedRegularFileMode(0o100755) !== "100755"
) {
  throw new Error("Review snapshot file-mode normalization is not Git-portable");
}

if (
  inventoryEntryHash({ path: "probe", objectType: "file", mode: "100644", contentHash: "a" }) ===
  inventoryEntryHash({ path: "probe", objectType: "file", mode: "100755", contentHash: "a" })
) {
  throw new Error("Review snapshot does not distinguish executable mode changes");
}
if (
  inventoryEntryHash({ path: "probe", objectType: "symlink", mode: "120777", target: "a" }) ===
  inventoryEntryHash({ path: "probe", objectType: "symlink", mode: "120777", target: "b" })
) {
  throw new Error("Review snapshot does not distinguish symlink target changes");
}

for (const relativePath of paths) {
  const absolutePath = resolve(root, relativePath);
  const metadata = await lstat(absolutePath);
  const entry = metadata.isSymbolicLink()
    ? {
        path: relativePath,
        objectType: "symlink",
        mode: "120000",
        target: await readlink(absolutePath)
      }
    : metadata.isFile()
      ? {
          path: relativePath,
          objectType: "file",
          mode: normalizedRegularFileMode(metadata.mode),
          contentHash: createHash("sha256").update(await readFile(absolutePath)).digest("hex")
        }
      : null;
  if (!entry) throw new Error(`Unsupported review snapshot object: ${relativePath}`);
  inventoryHash.update(inventoryEntryHash(entry), "ascii");
  inventoryHash.update("\0");
}

console.log(`${inventoryHash.digest("hex")} files=${paths.length}`);
