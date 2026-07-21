import { readdir, readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const ignoredDirectories = new Set([
  ".git",
  ".next",
  ".terraform",
  ".turbo",
  "coverage",
  "dist",
  "node_modules"
]);
const textExtensions = new Set([
  ".css",
  ".hcl",
  ".js",
  ".json",
  ".jsonc",
  ".md",
  ".mjs",
  ".toml",
  ".ts",
  ".tsx",
  ".tf",
  ".yaml",
  ".yml"
]);
const namedTextFiles = new Set([
  ".dockerignore",
  ".env.example",
  ".gitignore",
  ".npmrc",
  "Dockerfile"
]);

async function collect(directory) {
  const paths = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await collect(path)));
    else if (textExtensions.has(extname(entry.name)) || namedTextFiles.has(entry.name)) paths.push(path);
  }
  return paths;
}

const failures = [];
const paths = await collect(root);
for (const path of paths) {
  const contents = await readFile(path, "utf8");
  const relativePath = path.slice(root.length + 1);
  if (!contents.endsWith("\n")) failures.push(`${relativePath}: missing final newline`);
  if (contents.includes("\r")) failures.push(`${relativePath}: contains carriage-return characters`);
  for (const [index, line] of contents.split("\n").entries()) {
    if (/[ \t]+$/.test(line)) failures.push(`${relativePath}:${index + 1}: trailing whitespace`);
    if (/^(<<<<<<< |=======|>>>>>>> )/.test(line)) {
      failures.push(`${relativePath}:${index + 1}: unresolved conflict marker`);
    }
  }
}

if (failures.length > 0) {
  throw new Error(`Whitespace gate failed:\n${failures.join("\n")}`);
}

console.log(`Whitespace gate valid files=${paths.length}`);
