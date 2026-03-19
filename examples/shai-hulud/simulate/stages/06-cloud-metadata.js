/**
 * Stage 6 — Cloud metadata theft
 *
 * Shai-Hulud attempts to access cloud instance metadata endpoints to
 * steal temporary credentials:
 *   - AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
 *   - Azure: http://168.63.129.16/metadata/identity/oauth2/token
 *   - GCP: http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
 *
 * These are link-local addresses that only work from within cloud VMs,
 * but the connection attempt itself is suspicious and detectable.
 *
 * kntrl detection:
 *   - Rego rule 4: blocks npm ancestry from metadata IPs (169.254.169.254, 168.63.129.16)
 *   - YAML allow_metadata: false — kernel-level cgroup filter drops packets
 *   - YAML blocked_chains: blocks curl/wget from npm ancestry
 */

const { execSync } = require("child_process");

const endpoints = [
  {
    name: "AWS IMDSv1",
    cmd: `curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
  },
  {
    name: "AWS IMDSv2 (token request)",
    cmd: `curl -s -m 3 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token`,
  },
  {
    name: "Azure IMDS",
    cmd: `curl -s -m 3 -H "Metadata: true" "http://168.63.129.16/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"`,
  },
  {
    name: "GCP metadata",
    cmd: `curl -s -m 3 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`,
  },
];

for (const ep of endpoints) {
  console.log(`  [metadata] Attempting ${ep.name} ...`);
  try {
    execSync(ep.cmd, { stdio: "inherit", timeout: 6000 });
    console.log(`  [metadata] WARNING: ${ep.name} succeeded (should be blocked!)`);
  } catch (err) {
    if (err.signal === "SIGKILL") {
      console.log(`  [metadata] curl killed by kntrl (SIGKILL)`);
    } else {
      console.log(`  [metadata] ${ep.name} blocked or unreachable — expected`);
    }
  }
}
