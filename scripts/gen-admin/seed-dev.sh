#!/usr/bin/env bash
set -e

VERBOSE=false
REMOTE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default to empty, will attempt to find in toml if unset
DB_NAME="${database_name:-}" 

for arg in "$@"; do
  case $arg in
    --verbose|-v) VERBOSE=true ;;
    --remote|-r) REMOTE=true ;;
    --db=*) DB_NAME="${arg#*=}" ;;
  esac
done

# If DB_NAME not provided via flag, read from wrangler.toml
if [ -z "$DB_NAME" ]; then
  # Extract database_name from d1_databases section
  # Note: This regex is brittle if toml formatting changes
  DB_NAME=$(grep -A 5 '
$$
\[d1_databases
$$\]' "$PROJECT_ROOT/wrangler.toml" | \
    grep "database_name" | \
    head -n 1 | \
    cut -d'"' -f2)
fi

# Fallback default if extraction failed
if [ -z "$DB_NAME" ]; then
    DB_NAME="meshtastic-deadlight"
fi

if [ "$VERBOSE" = true ]; then
  echo "Using database: $DB_NAME"
fi

# Prompt for credentials
read -p "Enter admin username: " ADMIN_USER
read -p "Enter admin email: " ADMIN_EMAIL
read -s -p "Enter admin password: " ADMIN_PASS
echo ""

# Hash the password using the lib
# We pass pass via stdin to avoid process listing exposure (security fix)
read -r HASHED_PASS SALT <<< $(echo "$ADMIN_PASS" | node -e "
  import { hashPassword } from '../lib.deadlight/core/src/auth/password.js';
  
  let data = '';
  process.stdin.on('data', chunk => data += chunk);
  process.stdin.on('end', () => {
    hashPassword(data.trim()).then(({ hash, salt }) => {
      console.log(\`\${hash} \${salt}\`);
    });
  });
")

# Set wrangler flags
WRANGLER_FLAGS="--local"
if [ "$REMOTE" = true ]; then
  WRANGLER_FLAGS="--remote"
fi

# Check for existing user
if [ "$VERBOSE" = true ]; then
  echo "Checking for existing user..."
fi

# We capture output and suppress errors for the check to handle first-run scenarios cleanly
USER_COUNT=$(wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --command \
  "SELECT COUNT(*) AS count FROM users WHERE username = '$ADMIN_USER' OR email = '$ADMIN_EMAIL';" \
  --json 2>/dev/null | jq -r '(.results[0].count // 0)' 2>/dev/null || echo "0")

if [ "$USER_COUNT" -gt 0 ]; then
  echo "Error: User '$ADMIN_USER' or '$ADMIN_EMAIL' already exists."
  exit 1
fi

# Create a temporary seed file
TMP_SEED=$(mktemp)
sed \
  -e "s#{{USERNAME}}#$ADMIN_USER#g" \
  -e "s#{{EMAIL}}#$ADMIN_EMAIL#g" \
  -e "s#{{PASSWORD}}#$HASHED_PASS#g" \
  -e "s#{{SALT}}#$SALT#g" \
  "$SCRIPT_DIR/seed-template.sql" > "$TMP_SEED"

# Execute
if [ "$VERBOSE" = true ]; then
  echo "Seeding database..."
fi

wrangler d1 execute "$DB_NAME" $WRANGLER_FLAGS --file="$TMP_SEED" 2>/dev/null

rm "$TMP_SEED"
echo "Admin user created successfully in database: $DB_NAME"