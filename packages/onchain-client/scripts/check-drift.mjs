// Fails when the checked-in generated client no longer matches the IDL.
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { existsSync } from "node:fs";
import { generateInto, idlPath, packageRoot } from "./generate.mjs";

// When the program has been built locally, the checked-in IDL must match the
// build output — otherwise the client is generated from a stale ABI.
const builtIdl = resolve(packageRoot, "../../onchain/target/idl/onelayer_registry.json");
if (existsSync(builtIdl) && readFileSync(builtIdl, "utf8") !== readFileSync(idlPath, "utf8")) {
  process.stderr.write(`checked-in IDL differs from the build output\nrun: cp ${builtIdl} ${idlPath} && npm run generate\n`);
  process.exit(1);
}

function tree(directory) {
  const files = new Map();
  const walk = (current, prefix) => {
    for (const entry of readdirSync(current).sort()) {
      const full = join(current, entry);
      const relative = prefix === "" ? entry : `${prefix}/${entry}`;
      if (statSync(full).isDirectory()) walk(full, relative);
      else files.set(relative, readFileSync(full, "utf8"));
    }
  };
  walk(directory, "");
  return files;
}

const committed = resolve(packageRoot, "src/generated");
const scratch = join(mkdtempSync(join(tmpdir(), "onelayer-codama-")), "generated");
try {
  await generateInto(scratch);
  const expected = tree(scratch);
  const actual = tree(committed);
  const drift = [];
  for (const [path, content] of expected) {
    if (!actual.has(path)) drift.push(`missing: ${path}`);
    else if (actual.get(path) !== content) drift.push(`changed: ${path}`);
  }
  for (const path of actual.keys()) if (!expected.has(path)) drift.push(`unexpected: ${path}`);
  if (drift.length > 0) {
    process.stderr.write(`generated client drifted from the IDL:\n${drift.join("\n")}\nrun: npm run generate\n`);
    process.exit(1);
  }
  process.stdout.write(`generated client matches the IDL (${expected.size} files)\n`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
