// Checks that every selector the renderer uses actually exists in the markup.
//
//   node tools/check-ui.mjs
//
// The frontend has no build step and no test runner, so a renamed `data-field`
// fails silently: `field("x")` returns null and the next property access throws
// at runtime, on a screen that may be hard to reach. This is the cheapest thing
// that turns that into a failure at the point of the edit.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const html = readFileSync(join(root, "index.html"), "utf8");
const js = readFileSync(join(root, "main.js"), "utf8");

/** Every value of `attribute` present in the markup. */
function declared(attribute) {
  return new Set(
    [...html.matchAll(new RegExp(`${attribute}="([^"]+)"`, "g"))].map((m) => m[1]),
  );
}

/** Every value the script looks up via `pattern`. */
function used(pattern) {
  return new Set([...js.matchAll(pattern)].map((m) => m[1]));
}

const checks = [
  {
    what: "data-field",
    declared: declared("data-field"),
    // field("x"), setText("x", …), setError("x", …) all resolve a data-field.
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

  // Unused declarations are not errors — some are written by Rust-driven
  // status rendering — but a typo usually shows up as a pair, so they are
  // worth surfacing.
  const unused = [...check.declared].filter((name) => !check.used.has(name));
  if (unused.length > 0) {
    console.warn(`  ${check.what}: declared but never referenced — ${unused.join(", ")}`);
  }
}

// Panes and tabs have to agree, or a tab selects nothing.
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
