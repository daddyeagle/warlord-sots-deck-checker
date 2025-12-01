#!/bin/bash
# Sync static site files from docs/ to backend/ (for Railway deploy)
# Usage: bash sync_static.sh

set -e

SRC="docs"
DEST="backend"

# List of files/folders to sync (add more as needed)
INCLUDE=(
  "index.html"
  "admin.html"
  "discord_tokens.json"
  "token_requests.json"
  "warlord_configuration.json"
  "static.json"
  "_redirects"
  ".nojekyll"
  "assets"
  "events"
)

# Remove old static files from backend (except backend code)
for item in "${INCLUDE[@]}"; do
  if [ -e "$DEST/$item" ]; then
    rm -rf "$DEST/$item"
  fi
done

# Copy new static files from docs to backend
for item in "${INCLUDE[@]}"; do
  if [ -e "$SRC/$item" ]; then
    cp -r "$SRC/$item" "$DEST/"
  fi
done

echo "Static files synced from $SRC/ to $DEST/"
