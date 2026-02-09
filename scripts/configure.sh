#!/usr/bin/env bash
set -euo pipefail
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[configure] .env created"
else
  echo "[configure] .env exists"
fi
