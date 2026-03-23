/**
 * Stage 1 — Credential Harvesting
 *
 * The Shai-Hulud worm reads npm tokens, cloud credentials, and SSH keys
 * from the build environment. This is the first thing the worm does after
 * gaining code execution via postinstall.
 *
 * kntrl detection:
 *   - file.monitored_paths: alerts on reads to .npmrc, .aws/, .ssh/, etc.
 *   - file.monitored_env_vars: alerts on access to NPM_TOKEN, GITHUB_TOKEN, etc.
 *
 * NOTE: This stage uses fs.openSync() (not fs.accessSync/statSync) because
 * kntrl's BPF traces the openat syscall. access() and stat() are different
 * syscalls that are not monitored.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const home = os.homedir();

// --- Credential files the worm targets ---
const credFiles = [
  { path: path.join(home, ".npmrc"),             desc: "npm auth token" },
  { path: path.join(home, ".aws", "credentials"),desc: "AWS credentials" },
  { path: path.join(home, ".ssh", "id_rsa"),     desc: "SSH private key" },
  { path: path.join(home, ".ssh", "id_ed25519"), desc: "SSH ed25519 key" },
  { path: path.join(home, ".config", "gh", "hosts.yml"), desc: "GitHub CLI token" },
  { path: path.join(home, ".kube", "config"),    desc: "Kubernetes config" },
  { path: path.join(home, ".azure", "azureProfile.json"), desc: "Azure profile" },
  { path: path.join(home, ".config", "gcloud", "application_default_credentials.json"), desc: "GCP credentials" },
];

console.log("  [harvest] Scanning credential files (via openat syscall)...");

const found = [];
for (const cred of credFiles) {
  try {
    // Use fs.openSync + fs.closeSync to trigger the openat syscall.
    // This is what the real worm does (reads file contents).
    // kntrl's BPF trace_openat captures this and reports it.
    const fd = fs.openSync(cred.path, "r");
    const stat = fs.fstatSync(fd);
    // Read first 64 bytes to simulate credential extraction (SAFE: we discard it)
    const buf = Buffer.alloc(Math.min(64, stat.size));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    console.log(`  [harvest] FOUND: ${cred.desc} (${cred.path}, ${stat.size} bytes)`);
    found.push(cred.desc);
  } catch {
    console.log(`  [harvest] not found: ${cred.path}`);
  }
}

// --- Environment variables the worm steals ---
// The worm reads /proc/self/environ to harvest all env vars at once.
// kntrl monitors this file when monitored_env_vars is configured.
console.log("\n  [harvest] Reading /proc/self/environ (triggers env var monitoring)...");
try {
  const fd = fs.openSync("/proc/self/environ", "r");
  const buf = Buffer.alloc(4096);
  fs.readSync(fd, buf, 0, buf.length, 0);
  fs.closeSync(fd);
  console.log("  [harvest] /proc/self/environ opened successfully");
} catch {
  console.log("  [harvest] /proc/self/environ not available (not on Linux?)");
}

const envVars = [
  "NPM_TOKEN", "NPM_AUTH_TOKEN", "NODE_AUTH_TOKEN",
  "GITHUB_TOKEN", "GH_TOKEN",
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "DOCKER_AUTH_CONFIG",
  "CI_JOB_TOKEN", "GITLAB_TOKEN", "RUNNER_TOKEN",
];

console.log("\n  [harvest] Checking environment variables...");
const foundEnv = [];
for (const v of envVars) {
  if (process.env[v]) {
    // SAFE: Only report presence, never print actual values
    console.log(`  [harvest] FOUND: $${v} is set (${process.env[v].length} chars)`);
    foundEnv.push(v);
  }
}

console.log(`\n  [harvest] Summary: ${found.length} credential files, ${foundEnv.length} env vars found`);
console.log(`  [harvest] Real worm would now exfiltrate these to webhook.site...`);
