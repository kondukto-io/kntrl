/**
 * Stage 8 — Dead man's switch (evidence destruction)
 *
 * When the worm detects that its exfiltration channels are blocked or
 * its process is being monitored, it activates a "dead man's switch"
 * that attempts to destroy evidence and cause damage:
 *   - shred: secure-delete credential files
 *   - rm -rf: delete project files, node_modules, .git
 *   - xargs: bulk file deletion
 *
 * kntrl detection:
 *   - YAML blocked_executables: shred → SIGKILL at execve (kernel level)
 *   - YAML blocked_chains: shred/rm/xargs from npm ancestry
 *   - File protection: protected_paths prevent writes to /etc/sudoers, etc.
 *
 * SAFE: This simulation targets only temp files created by the sim.
 * shred/rm commands will be killed by kntrl before they execute.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// Create safe temp targets for the destruction simulation
const tmpDir = path.join(os.tmpdir(), "shai-hulud-targets-" + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });
fs.writeFileSync(path.join(tmpDir, "fake-npmrc"), "//registry.npmjs.org/:_authToken=npm_FAKE_TOKEN\n");
fs.writeFileSync(path.join(tmpDir, "fake-ssh-key"), "-----BEGIN FAKE KEY-----\nNOT_A_REAL_KEY\n");

// --- Attempt 1: shred (kernel-level SIGKILL via blocked_executables) ---
console.log("  [destroy] Attempting shred on stolen credential copies ...");
try {
  execSync(`shred -vfz -n 3 "${path.join(tmpDir, "fake-npmrc")}"`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [destroy] WARNING: shred succeeded (kntrl should SIGKILL this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [destroy] shred killed by kntrl (SIGKILL) — blocked_executables working");
  } else {
    console.log("  [destroy] shred failed — expected (blocked or not installed)");
  }
}

// --- Attempt 2: rm -rf (blocked_chains: rm from npm) ---
console.log("  [destroy] Attempting rm -rf on temp targets ...");
try {
  execSync(`rm -rf "${tmpDir}"`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [destroy] rm completed (may or may not be blocked depending on config)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [destroy] rm killed by kntrl (SIGKILL) — process chain block working");
  } else {
    console.log("  [destroy] rm failed — expected");
  }
}

// Cleanup if anything remains
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {}
