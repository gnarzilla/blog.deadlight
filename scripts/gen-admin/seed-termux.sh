#!/usr/bin/env bash
set -e

DB_NAME=$(node -e "
  import fs from 'fs';
  import toml from '@iarna/toml';
  const data = toml.parse(fs.readFileSync('wrangler.toml', 'utf-8'));
  console.log(data.d1_databases[0].database_name);
")

REMOTE="--remote"
VERBOSE=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

read -p "Enter admin username: " ADMIN_USER
read -p "Enter admin email: " ADMIN_EMAIL
read -s -p "Enter admin password: " ADMIN_PASS
echo

# Generate hash + salt using lib.deadlight PBKDF2
HASH_AND_SALT=$(node --input-type=module -e "
  import { hashPassword } from '../lib.deadlight/core/src/auth/password.js';
  hashPassword(process.argv[1]).then(r => {
    console.log(r.hash + ' ' + r.salt);
  });
" "$ADMIN_PASS")

HASHED_PASS=$(echo "$HASH_AND_SALT" | cut -d' ' -f1)
SALT=$(echo "$HASH_AND_SALT" | cut -d' ' -f2)

echo "Generated hash: $HASHED_PASS"
echo "Generated salt: $SALT"

# Insert into D1 (note: column is 'password', not 'password_hash')
npx wrangler d1 execute "$DB_NAME" $REMOTE --command "
  INSERT INTO users (username, email, password, salt, role)
  VALUES ('$ADMIN_USER', '$ADMIN_EMAIL', '$HASHED_PASS', '$SALT', 'admin');
"

echo "Admin user created successfully in database: $DB_NAME"
