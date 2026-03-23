#!/usr/bin/env bash
#
# Shai-Hulud worm simulation runner
#
# This script demonstrates the full Shai-Hulud npm worm attack chain
# while kntrl monitors and blocks each stage.
#
# Usage:
#   # Terminal 1: Start kntrl with Shai-Hulud detection rules
#   sudo kntrl trace --rules-dir ./examples/shai-hulud/
#
#   # Terminal 2: Run the simulation
#   cd examples/shai-hulud/simulate
#   ./run-all.sh
#
# What happens:
#   1. npm install triggers postinstall → node index.js
#   2. Each stage spawns processes (curl, wget, bash, shred, nc, ...)
#   3. kntrl detects the process chains and blocks them via:
#      - eBPF cgroup filter (network packets dropped)
#      - eBPF SIGKILL (blocked executables killed at execve)
#      - OPA policy engine (ancestry + domain rules deny the connection)
#   4. Check kntrl output for detection events

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " Shai-Hulud Worm Simulation"
echo "============================================================"
echo
echo " Rules directory: $RULES_DIR"
echo " Simulation:      $SCRIPT_DIR"
echo

# Check if kntrl is running
if ! pgrep -x kntrl >/dev/null 2>&1; then
    echo "WARNING: kntrl is not running!"
    echo "Start it first with:"
    echo "  sudo kntrl trace --rules-dir $RULES_DIR"
    echo
    read -p "Continue without kntrl? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Running simulation via npm install (triggers postinstall hook)..."
echo

cd "$SCRIPT_DIR"

# npm install triggers postinstall → node index.js → each attack stage
npm install --ignore-scripts=false 2>&1

echo
echo "Done. Check kntrl output for detection events."
