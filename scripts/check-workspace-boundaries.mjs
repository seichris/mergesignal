import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");
const sourceExtensions = new Set([".ts", ".tsx", ".mjs", ".js"]);

async function workspaceDirectories(parent) {
  const directory = resolve(root, parent);
  return (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(directory, entry.name));
}

async function collectSources(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (["dist", ".next", "node_modules"].includes(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await collectSources(path)));
    else if (sourceExtensions.has(extname(entry.name))) files.push(path);
  }
  return files;
}

const packageDirectories = [
  ...(await workspaceDirectories("apps")),
  ...(await workspaceDirectories("packages"))
];
const packages = new Map();
for (const directory of packageDirectories) {
  const manifest = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
  if (typeof manifest.name !== "string" || !manifest.name.startsWith("@mergesignal/")) {
    throw new Error(`${relative(root, directory)} has an invalid workspace package name`);
  }
  if (packages.has(manifest.name)) throw new Error(`Duplicate workspace package: ${manifest.name}`);
  packages.set(manifest.name, { directory, manifest });
}

const failures = [];
const dependencyGraph = new Map([...packages.keys()].map((name) => [name, new Set()]));
const importPattern = /(?:\bfrom\s*|\bimport\s*\(\s*)["']([^"']+)["']/g;

for (const [name, workspace] of packages) {
  const declared = {
    ...(workspace.manifest.dependencies ?? {}),
    ...(workspace.manifest.devDependencies ?? {})
  };
  for (const [dependency, version] of Object.entries(declared)) {
    if (!packages.has(dependency)) continue;
    if (version !== "workspace:*") {
      failures.push(`${name}: internal dependency ${dependency} must use workspace:*`);
    }
    dependencyGraph.get(name).add(dependency);
    if (dependency.endsWith("/web") || dependency.endsWith("/worker")) {
      failures.push(`${name}: workspace packages and apps cannot depend on deployable apps`);
    }
  }

  const sources = await collectSources(workspace.directory);
  for (const path of sources) {
    const contents = await readFile(path, "utf8");
    for (const match of contents.matchAll(importPattern)) {
      const specifier = match[1];
      if (specifier === undefined) continue;
      if (specifier.startsWith(".")) {
        const target = resolve(dirname(path), specifier);
        if (target !== workspace.directory && !target.startsWith(`${workspace.directory}${sep}`)) {
          failures.push(`${relative(root, path)}: relative import escapes its package`);
        }
        continue;
      }

      const internalName = [...packages.keys()].find(
        (candidate) => specifier === candidate || specifier.startsWith(`${candidate}/`)
      );
      if (internalName !== undefined && declared[internalName] === undefined) {
        failures.push(`${relative(root, path)}: ${internalName} is imported but not declared`);
      }

      if (
        name === "@mergesignal/workflows" &&
        (specifier.startsWith("node:") ||
          (specifier.startsWith("@mergesignal/") && specifier !== "@mergesignal/workflows") ||
          (specifier.startsWith("@temporalio/") && specifier !== "@temporalio/workflow"))
      ) {
        failures.push(`${relative(root, path)}: deterministic workflows import forbidden module ${specifier}`);
      }
      if (
        name === "@mergesignal/web" &&
        (specifier.startsWith("@temporalio/") || specifier.startsWith("@mergesignal/workflows"))
      ) {
        failures.push(`${relative(root, path)}: web ingress must use the database inbox/outbox boundary`);
      }
    }
  }
}

const visiting = new Set();
const visited = new Set();
function visit(name, path = []) {
  if (visiting.has(name)) {
    failures.push(`Workspace dependency cycle: ${[...path, name].join(" -> ")}`);
    return;
  }
  if (visited.has(name)) return;
  visiting.add(name);
  for (const dependency of dependencyGraph.get(name)) visit(dependency, [...path, name]);
  visiting.delete(name);
  visited.add(name);
}
for (const name of packages.keys()) visit(name);

if (failures.length > 0) {
  throw new Error(`Workspace boundary gate failed:\n${[...new Set(failures)].join("\n")}`);
}

console.log(`Workspace boundaries valid packages=${packages.size}`);
