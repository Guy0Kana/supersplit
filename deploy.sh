#!/usr/bin/env bash
# Usage: ./deploy.sh production|staging   (run from the app directory on the VM)
set -euo pipefail
target="${1:-production}"
case "$target" in
  production) app=super-split ;;
  staging) app=super-split-staging ;;
  *) echo "Usage: $0 production|staging" >&2; exit 1 ;;
esac
git pull --ff-only
npm ci --omit=dev
if pm2 describe "$app" >/dev/null 2>&1; then
  pm2 reload ecosystem.config.js --only "$app" --update-env
else
  pm2 start ecosystem.config.js --only "$app"
fi
pm2 save
echo "Deployed $app"
