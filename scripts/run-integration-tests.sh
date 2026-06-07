#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Setup ANSI colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}       RBAT End-to-End Integration Test Suite        ${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Define cleanup function
cleanup() {
  echo -e "\n${YELLOW}🧹 Cleaning up background processes and containers...${NC}"
  
  if [ -n "$SERVER_PID" ]; then
    echo "Stopping rbat-server (PID: $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  
  if [ -n "$CLIENT_PID" ]; then
    echo "Stopping rbat-client (PID: $CLIENT_PID)..."
    kill "$CLIENT_PID" 2>/dev/null || true
  fi
  
  echo "Stopping Redis and MinIO Docker containers..."
  docker rm -f rbat-test-redis rbat-test-minio 2>/dev/null || true
  
  # Remove temp files
  rm -f /tmp/dummy_binary.bin 2>/dev/null || true
  
  echo -e "${GREEN}✓ Cleanup complete.${NC}"
}

# Register the cleanup function to run on exit, interrupt, or termination
trap cleanup EXIT

# 1. Start Docker Containers for Redis and MinIO
echo -e "\n${YELLOW}🚀 1. Checking Docker daemon availability...${NC}"
if ! docker info >/dev/null 2>&1; then
  echo -e "${YELLOW}⚠️  Docker daemon is not running or unreachable.${NC}"
  echo -e "To run E2E integration tests locally, please start Docker (or Docker Desktop)."
  if [ "$CI" = "true" ]; then
    echo -e "${RED}❌ FAILED: Docker daemon is required for integration tests in CI!${NC}"
    exit 1
  else
    echo -e "${YELLOW}Skipping E2E integration tests locally. Proceeding...${NC}"
    exit 0
  fi
fi

echo -e "${GREEN}✓ Docker daemon is available.${NC}"
docker rm -f rbat-test-redis rbat-test-minio 2>/dev/null || true

docker run -d --name rbat-test-redis -p 6379:6379 redis:7-alpine
docker run -d --name rbat-test-minio -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=admin_user \
  -e MINIO_ROOT_PASSWORD=super_secure_password_change_me \
  minio/minio:latest server /data --console-address ":9001"

# 2. Wait for MinIO and Redis to be fully online
echo -e "\n${YELLOW}⌛ 2. Waiting for MinIO and Redis to be healthy...${NC}"
RETRIES=15
until curl -s -f http://localhost:9000/minio/health/live > /dev/null || [ $RETRIES -eq 0 ]; do
  echo "Waiting for MinIO... ($RETRIES retries left)"
  sleep 2
  RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
  echo -e "${RED}❌ MinIO failed to start in time.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ MinIO is online.${NC}"

# Check Redis connection
RETRIES=10
until docker exec rbat-test-redis redis-cli ping | grep PONG > /dev/null || [ $RETRIES -eq 0 ]; do
  echo "Waiting for Redis... ($RETRIES retries left)"
  sleep 1
  RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
  echo -e "${RED}❌ Redis failed to start in time.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Redis is online.${NC}"

# 3. Clean up old analysis store
echo -e "\n${YELLOW}📂 3. Setting up test directories...${NC}"
rm -rf /tmp/rbat-test-store
mkdir -p /tmp/rbat-test-store

# 4. Build projects
echo -e "\n${YELLOW}🏗️ 4. Building workspace projects...${NC}"
echo "Building rbat-server..."
cargo build -p rbat-server

echo "Installing client dependencies..."
pnpm --dir rbat-client install --frozen-lockfile

echo "Building rbat-client Next.js production build..."
pnpm --dir rbat-client build

# 5. Start rbat-server
echo -e "\n${YELLOW}🚀 5. Launching rbat-server daemon...${NC}"
export HOST=127.0.0.1
export PORT=8080
export MINIO_ROOT_USER=admin_user
export MINIO_ROOT_PASSWORD=super_secure_password_change_me
export MINIO_ENDPOINT=http://localhost:9000
export WEBHOOK_TARGET_URL=http://localhost:3000/api/webhook
export WEBHOOK_SECRET=whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD
export RUN_MODE=development

./target/debug/rbat-server > /tmp/rbat-test-server.log 2>&1 &
SERVER_PID=$!
echo "rbat-server started with PID: $SERVER_PID"

# Wait for server HTTP health check
RETRIES=10
until curl -s -f http://localhost:8080/health > /dev/null || [ $RETRIES -eq 0 ]; do
  echo "Waiting for rbat-server to initialize... ($RETRIES retries left)"
  sleep 1
  RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
  echo -e "${RED}❌ rbat-server failed to start.${NC}"
  echo "Last 15 lines of server log:"
  tail -n 15 /tmp/rbat-test-server.log
  exit 1
fi
echo -e "${GREEN}✓ rbat-server is ready.${NC}"

# 6. Start rbat-client
echo -e "\n${YELLOW}🚀 6. Launching rbat-client dashboard...${NC}"
export PORT=3000
export NODE_ENV=development
export GRPC_SERVER_URL=127.0.0.1:8080
export WEBHOOK_RECEIVER_URL=http://localhost:8080/webhooks
export REDIS_URL=redis://127.0.0.1:6379
export ANALYSIS_STORE_PATH=/tmp/rbat-test-store

pnpm --dir rbat-client start > /tmp/rbat-test-client.log 2>&1 &
CLIENT_PID=$!
echo "rbat-client started with PID: $CLIENT_PID"

# Wait for client HTTP response
RETRIES=20
until curl -s -f http://localhost:3000/ > /dev/null || [ $RETRIES -eq 0 ]; do
  echo "Waiting for rbat-client to initialize... ($RETRIES retries left)"
  sleep 1
  RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
  echo -e "${RED}❌ rbat-client failed to start.${NC}"
  echo "Last 15 lines of client log:"
  tail -n 15 /tmp/rbat-test-client.log
  exit 1
fi
echo -e "${GREEN}✓ rbat-client is ready.${NC}"

# 7. Upload binary via Next.js client upload endpoint
echo -e "\n${YELLOW}📤 7. Triggering test upload via client API...${NC}"
echo "This is a dummy test binary file used to verify client-server integration." > /tmp/dummy_binary.bin

RESPONSE=$(curl -s -F "file=@/tmp/dummy_binary.bin" http://localhost:3000/api/upload)
echo "Upload response: $RESPONSE"

FILE_ID=$(echo "$RESPONSE" | grep -o '"file_id":"[^"]*' | grep -o '[^"]*$' || true)

if [ -z "$FILE_ID" ]; then
  echo -e "${RED}❌ Failed to extract file_id from upload response.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ File successfully uploaded and registered! File ID: $FILE_ID${NC}"

# 8. Poll the local store for the completed analysis webhook JSON file
echo -e "\n${YELLOW}⌛ 8. Waiting for analysis completion webhook...${NC}"
RETRIES=20
REPORT_FILE="/tmp/rbat-test-store/${FILE_ID}.json"

until [ -f "$REPORT_FILE" ] || [ $RETRIES -eq 0 ]; do
  echo "Waiting for report file to be written... ($RETRIES retries left)"
  sleep 2
  RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
  echo -e "${RED}❌ Integration test timed out. Webhook never arrived at the client.${NC}"
  echo "Last 20 lines of server log:"
  tail -n 20 /tmp/rbat-test-server.log
  echo "Last 20 lines of client log:"
  tail -n 20 /tmp/rbat-test-client.log
  exit 1
fi

echo -e "${GREEN}✓ Webhook report file successfully saved by client!${NC}"
cat "$REPORT_FILE" | json_pp 2>/dev/null || cat "$REPORT_FILE"

echo -e "\n${GREEN}🎉 SUCCESS: All integration validation checks passed!${NC}"
exit 0
