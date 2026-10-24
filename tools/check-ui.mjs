import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const html = readFileSync(join(root, "index.html"), "utf8");
const js = readFileSync(join(root, "main.js"), "utf8");

function declared(attribute) {
  return new Set(
    [...html.matchAll(new RegExp(`${attribute}="([^"]+)"`, "g"))].map((m) => m[1]),
  );
}

function used(pattern) {
  return new Set([...js.matchAll(pattern)].map((m) => m[1]));
}

const checks = [
  {
    what: "data-field",
    declared: declared("data-field"),
    used: used(/\b(?:field|setText|setError)\(\s*"([^"]+)"/g),
  },
  {
    what: "data-action",
    declared: declared("data-action"),
    used: used(/\[data-action="([^"]+)"\]/g),
  },
  {
    what: "data-pane",
    declared: declared("data-pane"),
    used: used(/showPane\(\s*"([^"]+)"\s*\)/g),
  },
  {
    what: "data-screen",
    declared: declared("data-screen"),
    used: used(/\bshow\(\s*"([^"]+)"\s*\)/g),
  },
  {
    what: "data-form",
    declared: declared("data-form"),
    used: used(/\[data-form="([^"]+)"\]/g),
  },
];

let failures = 0;

for (const check of checks) {
  const missing = [...check.used].filter((name) => !check.declared.has(name));
  if (missing.length > 0) {
    failures += missing.length;
    console.error(
      `✗ ${check.what}: used in main.js but absent from index.html — ${missing.join(", ")}`,
    );
  }

  const unused = [...check.declared].filter((name) => !check.used.has(name));
  if (unused.length > 0) {
    console.warn(`  ${check.what}: declared but never referenced — ${unused.join(", ")}`);
  }
}

const panes = declared("data-pane");
const tabs = declared("data-tab");
for (const tab of tabs) {
  if (!panes.has(tab)) {
    failures += 1;
    console.error(`✗ data-tab="${tab}" has no matching pane`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} broken selector(s).`);
  process.exit(1);
}
console.log("UI selectors are consistent.");
