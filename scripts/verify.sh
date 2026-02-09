#!/usr/bin/env bash
set -euo pipefail
node -v
npm -v
node --check src/server.js
echo "[verify] syntax ok"
