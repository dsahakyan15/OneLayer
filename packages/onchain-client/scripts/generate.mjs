// Regenerates src/generated from the checked-in Anchor IDL.
// Hand-written Borsh serialization, PDA seeds and account layouts are forbidden
// outside this generated tree (OL-C-32).
import { cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createFromRoot } from "codama";
import { rootNodeFromAnchor } from "@codama/nodes-from-anchor";
import { renderVisitor } from "@codama/renderers-js";

const here = dirname(fileURLToPath(import.meta.url));
export const packageRoot = resolve(here, "..");
export const idlPath = resolve(packageRoot, "../../onchain/idl/onelayer_registry.json");

// The renderer emits `<scratch>/package.json` plus `<scratch>/src/generated/**`.
// Only the module tree is kept: a nested package.json without `"type": "module"`
// would make Node treat the generated sources as CommonJS.
export async function generateInto(outputDirectory) {
  const idl = JSON.parse(readFileSync(idlPath, "utf8"));
  const scratch = `${outputDirectory}.codama`;
  rmSync(scratch, { recursive: true, force: true });
  await createFromRoot(rootNodeFromAnchor(idl)).accept(
    renderVisitor(scratch, { deleteFolderBeforeRendering: true, formatCode: false }),
  );
  rmSync(outputDirectory, { recursive: true, force: true });
  cpSync(resolve(scratch, "src/generated"), outputDirectory, { recursive: true });
  rmSync(scratch, { recursive: true, force: true });
  addExplicitExtensions(outputDirectory);
}

// The renderer emits bundler-style extensionless specifiers; Node ESM resolves
// neither those nor directory indexes. The rewrite is deterministic, so the
// drift check still compares like with like.
function addExplicitExtensions(directory) {
  for (const entry of readdirSync(directory)) {
    const full = join(directory, entry);
    if (statSync(full).isDirectory()) {
      addExplicitExtensions(full);
      continue;
    }
    if (!entry.endsWith(".ts")) continue;
    const source = readFileSync(full, "utf8");
    const rewritten = source.replace(/(from ')(\.[^']*)(')/g, (match, prefix, specifier, suffix) => {
      if (specifier.endsWith(".ts")) return match;
      const target = resolve(dirname(full), specifier);
      if (existsSync(target) && statSync(target).isDirectory()) return `${prefix}${specifier}/index.ts${suffix}`;
      return `${prefix}${specifier}.ts${suffix}`;
    });
    if (rewritten !== source) writeFileSync(full, rewritten);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const output = resolve(packageRoot, "src/generated");
  await generateInto(output);
  process.stdout.write(`generated ${output}\n`);
}
