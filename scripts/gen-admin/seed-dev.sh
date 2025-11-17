#!/usr/bin/env bash
set -e

VERBOSE=false
REMOTE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DB_NAME="${database_name:-meshtastic-deadlight}"

for arg in "$@"; do
  case $arg in
    --verbose|-v) VERBOSE=true ;;
    --remote|-r) REMOTE=true ;;
    --db=*) DB_NAME="${arg#*=}" ;;
  esac
done

# If DB_NAME not provided via flag, read from wrangler.toml
if [ -z "$DB_NAME" ]; then
  DB_NAME=$(grep -A 2 '
$$
\[d1_databases
$$\]' "$PROJECT_ROOT/wrangler.toml" | \
    grep "database_name" | \
    cut -d'"' -f2)
fi

if [ "$VERBOSE" = true ]; then
  echo "Using database: $DB_NAME"
fi

# Prompt for admin username/email and password
read -p "Enter admin username: " ADMIN_USER
read -p "Enter admin email: " ADMIN_EMAIL
read -s -p "Enter admin password: " ADMIN_PASS
echo

# Hash the password
read -r HASHED_PASS SALT <<< $(node -e "
  import { hashPassword } from '../lib.deadlight/core/src/auth/password.js';
  hashPassword(process.argv[1]).then(({ hash, salt }) => {
    console.log(\`\${hash} \${salt}\`);
  });
" "$ADMIN_PASS")

# Set wrangler flags
WRANGLER_FLAGS="--local"
if [ "$REMOTE" = true ]; then
  WRANGLER_FLAGS="--remote"
fi

<<<<<<< HEAD
# Check for existing user











if [ "$VERBOSE" = true ]; then
  EXISTS=$(wrangler d1 execute $DB_NAME $WRANGLER_FLAGS --command \
=======
# Check for existing user - FIXED: use $DB_NAME instead of hardcoded name
if [ "$VERBOSE" = true ]; then
  EXISTS=$(wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --command \
>>>>>>> refs/remotes/origin/main
    "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
    --json | jq -r 'to_entries[0].value.results[0].count // 0')
  echo "Duplicate check result: $EXISTS existing user(s) found."
else
<<<<<<< HEAD
  EXISTS=$(wrangler d1 execute $DB_NAME $WRANGLER_FLAGS --command \
=======
  EXISTS=$(wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --command \
>>>>>>> refs/remotes/origin/main
    "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
    --json 2>/dev/null | jq -r 'to_entries[0].value.results[0].count // 0')
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

# Execute the seed - FIXED: use $DB_NAME instead of hardcoded name
if [ "$VERBOSE" = true ]; then
<<<<<<< HEAD
  wrangler d1 execute $DB_NAME $WRANGLER_FLAGS --file="$TMP_SEED"
else
  wrangler d1 execute $DB_NAME $WRANGLER_FLAGS --file="$TMP_SEED" 2>/dev/null
=======
  wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --file="$TMP_SEED"
else
  wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --file="$TMP_SEED" 2>/dev/null
>>>>>>> refs/remotes/origin/main
fi

rm "$TMP_SEED"
echo "Admin user created successfully in database: $DB_NAME"                                                                                                                   
