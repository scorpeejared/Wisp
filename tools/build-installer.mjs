import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const dev = args.includes("--dev");
const checkOnly = args.includes("--check-only");
const target = args.find((a) => !a.startsWith("--"));

function fail(message) {
  console.error(`✗ ${message}`);
  process.exit(1);
}

if (!target) {
  fail("usage: node tools/build-installer.mjs <https://your-relay> [--check-only] [--dev]");
}

let url;
try {
  url = new URL(target);
} catch {
  fail(`${target} is not a URL`);
}

const local =
  ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
  url.hostname.endsWith(".localhost");

if (!dev) {
  if (url.protocol !== "https:") {
    fail("the relay must be https:// — over http everything except message contents crosses the network in the clear");
  }
  if (local) {
    fail("that is a local address; an installer built for it would not work on anyone else's machine");
  }
}

const base = url.origin;

async function get(path) {
  try {
    const response = await fetch(base + path, { signal: AbortSignal.timeout(15000) });
    return { status: response.status, body: await response.text() };
  } catch (error) {
    fail(`could not reach ${base}${path}: ${error.cause?.code ?? error.message}`);
  }
}

function unusableAddress(address) {
  const a = address.replace(/::\/64$/, "").toLowerCase();
  if (a === "unknown") return true;
  const v4 = a.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [x, y] = [Number(v4[1]), Number(v4[2])];
    return (
      x === 0 ||
      x === 10 ||
      x === 127 ||
      (x === 100 && y >= 64 && y <= 127) ||
      (x === 169 && y === 254) ||
      (x === 172 && y >= 16 && y <= 31) ||
      (x === 192 && y === 168)
    );
  }
  return a === "::1" || /^f[cd]/.test(a) || /^fe[89ab]/.test(a);
}

const health = await get("/health");
if (health.status !== 200 || health.body.trim() !== "ok") {
  fail(`${base}/health answered ${health.status} instead of "ok" — is the relay deployed and is this its address?`);
}
console.log(`✓ relay is online at ${base}`);

const whoami = await get("/v1/whoami");
let address = null;
try {
  address = JSON.parse(whoami.body).address;
} catch {}
if (whoami.status !== 200 || !address) {
  fail("the relay has no /v1/whoami — it is running an older build; redeploy it first");
}
if (!dev && unusableAddress(address)) {
  fail(
    `the relay sees this machine as "${address}", which is not a public address. ` +
      "It is reading the wrong header, so every visitor would share one rate-limit bucket. " +
      "Set WISP_CLIENT_IP_HEADER on the relay (cf-connecting-ip behind Cloudflare) and redeploy.",
  );
}
console.log(`✓ the relay sees this machine as ${address}`);
console.log("  Check that matches your real public IP (search \"what is my IP\"). If it shows a proxy's");
console.log("  address instead, the signup limits would apply to everyone at once — fix before shipping.");

if (checkOnly) {
  console.log("\n--check-only: not building.");
  process.exit(0);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const build = spawnSync("cargo", ["tauri", "build"], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
  env: { ...process.env, WISP_DEFAULT_RELAY_URL: base },
});

if (build.error || build.status !== 0) {
  fail("cargo tauri build failed. If it said there is no 'tauri' command, run: cargo install tauri-cli --version \"^2\"");
}

const exe = join(root, "target", "release", process.platform === "win32" ? "wisp-desktop.exe" : "wisp-desktop");
if (existsSync(exe)) {
  if (!readFileSync(exe).includes(Buffer.from(base))) {
    fail(`the built app does not contain ${base} — the relay address was not baked in; do not ship it`);
  }
  console.log(`✓ the app is built to talk to ${base}`);
} else {
  console.warn(`! could not find ${exe} to confirm the relay address was baked in`);
}

console.log(`\n✓ installers are in ${join(root, "target", "release", "bundle")}`);
