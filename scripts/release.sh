#!/bin/bash
# Cross-compiles pgdoctor for all supported platforms and publishes a
# GitHub release with the resulting tarballs. Usage: scripts/release.sh v0.1.0
set -euo pipefail

VERSION="${1:?usage: release.sh vX.Y.Z}"
cd "$(dirname "$0")/.."

OUT="dist"
rm -rf "$OUT"
mkdir -p "$OUT"

targets=(
  "darwin amd64"
  "darwin arm64"
  "linux amd64"
  "linux arm64"
)

for target in "${targets[@]}"; do
  read -r goos goarch <<<"$target"
  name="pgdoctor-${goos}-${goarch}"
  echo "Building ${name}..."
  GOOS="$goos" GOARCH="$goarch" go build -o "${OUT}/${name}/pgdoctor" ./cmd/pgdoctor
  tar -C "${OUT}/${name}" -czf "${OUT}/${name}.tar.gz" pgdoctor
  rm -rf "${OUT}/${name}"
done

git tag "$VERSION"
git push origin "$VERSION"
gh release create "$VERSION" "${OUT}"/*.tar.gz \
  --title "pgdoctor ${VERSION}" \
  --notes "PostgreSQL Reliability Audit CLI. Install: curl -fsSL https://pgdoctor-api.megflow.com/install.sh | sh"

echo "Released ${VERSION}."
