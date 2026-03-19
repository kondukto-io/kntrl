/**
 * Shai-Hulud worm simulation — postinstall orchestrator
 *
 * This script mimics the real worm's postinstall entry point.
 * It runs each attack stage sequentially so kntrl can detect and block them.
 *
 * Process ancestry chain:  npm → node (this file) → [curl/wget/bash/shred/nc]
 *
 * Usage:
 *   # With kntrl active (recommended):
 *   sudo kntrl trace --rules-dir ../  &
 *   cd simulate && npm install
 *
 *   # Or standalone:
 *   node index.js
 */

const { execSync, spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const STAGES_DIR = path.join(__dirname, "stages");

const stages = [
  "01-credential-harvest.js",
  "02-exfil-webhook.js",
  "03-exfil-pastebin.js",
  "04-github-api.js",
  "05-github-raw.js",
  "06-cloud-metadata.js",
  "07-self-propagate.js",
  "08-dead-mans-switch.js",
  "09-reverse-shell.js",
];

console.log("=".repeat(60));
console.log(" SHAI-HULUD WORM SIMULATION");
console.log(" Each stage triggers a different kntrl detection rule.");
console.log("=".repeat(60));
console.log();

for (const stage of stages) {
  const file = path.join(STAGES_DIR, stage);
  const label = stage.replace(".js", "").replace(/^\d+-/, "").replace(/-/g, " ");

  console.log(`${"─".repeat(60)}`);
  console.log(`▶ Stage: ${label}`);
  console.log(`${"─".repeat(60)}`);

  try {
    execSync(`node "${file}"`, {
      stdio: "inherit",
      timeout: 10000,
    });
  } catch (err) {
    if (err.signal === "SIGKILL") {
      console.log(`  ✗ Process killed by kntrl (SIGKILL) — detection working!`);
    } else if (err.status) {
      console.log(`  ✗ Stage exited with code ${err.status}`);
    } else {
      console.log(`  ✗ Stage failed: ${err.message}`);
    }
  }
  console.log();
}

console.log("=".repeat(60));
console.log(" SIMULATION COMPLETE");
console.log(" Check kntrl output for detection events.");
console.log("=".repeat(60));
