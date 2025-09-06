#!/usr/bin/env bash
set -euo pipefail
REPO_SSH="${1:-git@github.com:USER/quantum-edge-hub-supreme.git}"
echo "Init repo and push to: $REPO_SSH"
git init
git add .
git commit -m "QEHS: initial import"
git branch -M main
git remote add origin "$REPO_SSH" || true
git push -u origin main
echo "Done."
