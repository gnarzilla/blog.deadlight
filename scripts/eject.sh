#!/bin/bash

# DEADLIGHT EJECT PROTOCOL
# Turns a Cloudflare-hosted instance into a local, offline-capable bunker.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}"
echo "┌──────────────────────────────────────────────┐"
echo "│           DEADLIGHT EJECT SEQUENCE           │"
echo "└──────────────────────────────────────────────┘"
echo -e "${NC}"
echo "This will download your live production database and configure"
echo "a local runtime. Cloudflare is not required to run the result."
echo ""

# 1. Check Prereqs
if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}[Error] sqlite3 is not installed. Please install it first.${NC}"
    exit 1
fi

if ! command -v wrangler &> /dev/null; then
    echo -e "${RED}[Error] wrangler is not installed. Run: npm install -g wrangler${NC}"
    exit 1
fi

# 2. Configuration
read -p "Enter your Cloudflare D1 Database Name (e.g., my-blog): " DB_NAME
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EXPORT_DIR="./eject_$TIMESTAMP"
DB_FILE="$EXPORT_DIR/content.sqlite"
SQL_DUMP="$EXPORT_DIR/dump.sql"

mkdir -p "$EXPORT_DIR"

# 3. Authenticate check
echo -e "\n${YELLOW}[1/4] Verifying Cloudflare connection...${NC}"
whoami=$(npx wrangler whoami 2>/dev/null) || true
if [[ $whoami == *"Not logged in"* ]]; then
    echo "Please log in to Cloudflare to access your database."
    npx wrangler login
fi

# 4. Export Data
echo -e "${YELLOW}[2/4] Downloading database from the Edge...${NC}"
# Use wrangler's export feature to get SQL statements
npx wrangler d1 export "$DB_NAME" --remote --output="$SQL_DUMP"

if [ ! -f "$SQL_DUMP" ]; then
    echo -e "${RED}[Error] Database export failed.${NC}"
    exit 1
fi

# 5. Rehydrate to Local SQLite
echo -e "${YELLOW}[3/4] Rehydrating local SQLite database...${NC}"
# We wrap this because D1 exports sometimes contain specific pragmas
sqlite3 "$DB_FILE" < "$SQL_DUMP"

# 6. Generate Local Runtime Config
echo -e "${YELLOW}[4/4] Generating local runtime configuration...${NC}"

# Create a local env file
cat > "$EXPORT_DIR/.env" << EOL
DB_PATH=./content.sqlite
JWT_SECRET=$(openssl rand -hex 32)
PORT=8080
EOL

# Create a Docker Compose for total independence
cat > "$EXPORT_DIR/docker-compose.yml" << EOL
version: '3'
services:
  deadlight-local:
    image: node:18-alpine
    working_dir: /app
    volumes:
      - ./content.sqlite:/app/content.sqlite
      - ../src:/app/src
      - ../package.json:/app/package.json
      - ../../lib.deadlight:/lib.deadlight
    command: sh -c "npm install && npm start"
    environment:
      - DATABASE_URL=file:/app/content.sqlite
      - NODE_ENV=production
    ports:
      - "8080:8080"
EOL

echo -e "${GREEN}"
echo "------------------------------------------------"
echo "EJECT COMPLETE."
echo "------------------------------------------------"
echo "Your data is located in: $EXPORT_DIR"
echo ""
echo "To run locally (requires Docker):"
echo "  cd $EXPORT_DIR"
echo "  docker compose up"
echo ""
echo "Your blog will be available at http://localhost:8080"
echo "You are now completely unanchored from Cloudflare."
echo -e "${NC}"
