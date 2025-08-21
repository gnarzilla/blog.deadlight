#!/usr/bin/env bash
set -euo pipefail

VERBOSE=false
REMOTE=false

for arg in "$@"; do
  case $arg in
    --verbose|-v) VERBOSE=true ;;
    --remote|-r) REMOTE=true ;;
  esac
done

# Prompt for admin details
read -p "Enter admin username: " ADMIN_USER
read -p "Enter admin email: " ADMIN_EMAIL
read -s -p "Enter admin password: " ADMIN_PASS
echo

# Hash the password via Node helper
read -r HASHED_PASS SALT <<< $(node ./scripts/gen-admin/hash-password.mjs "$ADMIN_PASS")

# Wrangler flags
WRANGLER_FLAGS="--local"
if [ "$REMOTE" = true ]; then
  WRANGLER_FLAGS="--remote"
fi

# Check for duplicates
EXISTS=$(wrangler d1 execute threat-level-midnight.db $WRANGLER_FLAGS \
  --command "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
  --json 2>/dev/null | jq -r '.[0].results[0].count')

if [ "$EXISTS" -gt 0 ]; then
  echo "❌ User with username '$ADMIN_USER' or email '$ADMIN_EMAIL' already exists. Aborting."
  exit 1
fi

# Create temp SQL insert
TMP_SEED=$(mktemp)
cat > "$TMP_SEED" <<EOF
INSERT INTO users (username, email, password, salt, role, created_at, updated_at)
VALUES (
  '$ADMIN_USER',
  '$ADMIN_EMAIL',
  '$HASHED_PASS',
  '$SALT',
  'admin',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);
EOF

# Execute
if [ "$VERBOSE" = true ]; then
  wrangler d1 execute threat-level-midnight.db $WRANGLER_FLAGS --file="$TMP_SEED"
else
  wrangler d1 execute threat-level-midnight.db $WRANGLER_FLAGS --file="$TMP_SEED" >/dev/null 2>&1
fi

rm "$TMP_SEED"
echo "✅ Admin user '$ADMIN_USER' created."
