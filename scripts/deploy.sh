#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

VERSION=$1
if [ -z "$VERSION" ]; then
  VERSION="unknown"
fi

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "🚀 Deploying RBAT Stack Version: ${GREEN}v$VERSION${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Get Docker registry configurations from env (with sensible fallbacks)
REGISTRY=${DOCKER_REGISTRY:-""}
NAMESPACE=${DOCKER_NAMESPACE:-"heritage-xion"}

if [ -n "$REGISTRY" ]; then
  REGISTRY_PREFIX="${REGISTRY}/"
else
  REGISTRY_PREFIX=""
fi

SERVER_IMAGE="${REGISTRY_PREFIX}${NAMESPACE}/rbat-server"
CLIENT_IMAGE="${REGISTRY_PREFIX}${NAMESPACE}/rbat-client"

echo -e "\n${BLUE}🐳 1. Building Docker Images...${NC}"

echo "Building Server Image: $SERVER_IMAGE:$VERSION (and latest)"
docker build -t "$SERVER_IMAGE:$VERSION" -t "$SERVER_IMAGE:latest" -f rbat-server/Dockerfile .

echo "Building Client Image: $CLIENT_IMAGE:$VERSION (and latest)"
docker build -t "$CLIENT_IMAGE:$VERSION" -t "$CLIENT_IMAGE:latest" -f rbat-client/Dockerfile .

echo -e "\n${BLUE}🔐 2. Authenticating with Docker Registry...${NC}"
if [ -n "$DOCKER_USERNAME" ] && [ -n "$DOCKER_PASSWORD" ]; then
  echo "Logging into registry: ${REGISTRY:-docker.io}"
  echo "$DOCKER_PASSWORD" | docker login "$REGISTRY" -u "$DOCKER_USERNAME" --password-stdin
else
  echo "Registry credentials not provided. Skipping docker login..."
fi

echo -e "\n${BLUE}📤 3. Pushing Docker Images to Registry...${NC}"
if [ -n "$DOCKER_USERNAME" ] || [ -n "$REGISTRY" ]; then
  echo "Pushing Server Images..."
  docker push "$SERVER_IMAGE:$VERSION"
  docker push "$SERVER_IMAGE:latest"

  echo "Pushing Client Images..."
  docker push "$CLIENT_IMAGE:$VERSION"
  docker push "$CLIENT_IMAGE:latest"
  echo -e "${GREEN}✓ Successfully pushed all images.${NC}"
else
  echo "⚠️ Skipping image push: No registry credentials or custom registry specified."
  echo "To enable pushing, run with DOCKER_USERNAME and DOCKER_PASSWORD env variables set."
fi

# Example remote update hook
# ssh deploy-user@production-host.example.com << EOF
#   cd /opt/rbat
#   export RELEASE_VERSION=$VERSION
#   docker compose pull rbat_server rbat_client
#   docker compose up -d --remove-orphans
# EOF

echo -e "\n${GREEN}✓ Production deployment hook completed successfully!${NC}"
exit 0
