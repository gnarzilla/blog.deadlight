#!/usr/bin/env bash
set -e

VERBOSE=false
REMOTE=false

for arg in "$@"; do
  case $arg in
    --verbose|-v) VERBOSE=true ;;
    --remote|-r) REMOTE=true ;;
  esac
done

# Prompt for admin username/email and password
read -p "Enter admin username: " ADMIN_USER
read -p "Enter admin email: " ADMIN_EMAIL
read -s -p "Enter admin password: " ADMIN_PASS
echo

# Hash the password
read -r HASHED_PASS SALT <<< $(node -e "
  import { hashPassword } from '../../lib.deadlight/core/src/auth/password.js';
  hashPassword(process.argv[1]).then(({ hash, salt }) => {
    console.log(\`\${hash} \${salt}\`);
  });
" "$ADMIN_PASS")

# Set wrangler flags
WRANGLER_FLAGS="--local"
if [ "$REMOTE" = true ]; then
  WRANGLER_FLAGS="--remote"
fi

# Check for existing user
if [ "$VERBOSE" = true ]; then
  EXISTS=$(wrangler d1 execute thatch-db $WRANGLER_FLAGS --command \
    "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
    --json | jq -r '.[0].results[0].count')
  echo "Duplicate check result: $EXISTS existing user(s) found."
else
  EXISTS=$(wrangler d1 execute thatch-db $WRANGLER_FLAGS --command \
    "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
    --json 2>/dev/null | jq -r '.[0].results[0].count')
fi

if [ "$EXISTS" -gt 0 ]; then
  echo "User with username '$ADMIN_USER' or email '$ADMIN_EMAIL' already exists. Aborting."
  exit 1
fi

# Create a temporary seed file from template
TMP_SEED=$(mktemp)
sed \
  -e "s#{{USERNAME}}#$ADMIN_USER#g" \
  -e "s#{{EMAIL}}#$ADMIN_EMAIL#g" \
  -e "s#{{PASSWORD}}#$HASHED_PASS#g" \
  -e "s#{{SALT}}#$SALT#g" \
  scripts/gen-admin/seed-template.sql > "$TMP_SEED"

# Execute the seed
if [ "$VERBOSE" = true ]; then
  wrangler d1 execute thatch-db $WRANGLER_FLAGS --file="$TMP_SEED"
else
  wrangler d1 execute thatch-db $WRANGLER_FLAGS --file="$TMP_SEED" 2>/dev/null
fi

rm "$TMP_SEED"
echo "Admin user created."