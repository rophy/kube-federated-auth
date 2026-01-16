#!/bin/bash
set -e

# Get version from git
VERSION=$(git describe --tags --always)
IMAGE="rophy/kube-federated-auth:${VERSION}"

echo "Building ${IMAGE} with VERSION=${VERSION}"

docker build \
  --build-arg VERSION="${VERSION}" \
  -t "${IMAGE}" \
  .

echo ""
echo "Successfully built: ${IMAGE}"
echo ""
echo "To push: docker push ${IMAGE}"
