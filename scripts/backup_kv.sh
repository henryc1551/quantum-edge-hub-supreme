#!/usr/bin/env bash
set -euo pipefail
# Uwaga: Deno KV w Deno Deploy jest zarządzane przez platformę.
# Na VPS (lokalny Deno KV) — snapshoty katalogu danych KV (jeśli użyjesz FILE KV).
# Poniżej placeholder — dostosuj jeśli podłączysz KV do pliku/katalogu.

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p backups
tar czf "backups/qehs-backup-$TS.tgz" public/ nginx/ scripts/ docker-compose.prod.yml .env.vps
echo "Backup wykonany: backups/qehs-backup-$TS.tgz"
