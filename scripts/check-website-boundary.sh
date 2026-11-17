#!/usr/bin/env bash
# Website source and deployment belong in tenuo-ai/website.
set -euo pipefail
cd "$(dirname "$0")/.."

failed=0
for path in \
  CNAME docs/CNAME docs/.bundle docs/_config.yml docs/_layouts docs/_includes \
  docs/_preview.py docs/preview.sh docs/_dev-server.mjs docs/index.html \
  docs/in-the-wild.md docs/demo.html docs/docs.html docs/early-access.html \
  docs/protocol.html docs/protocol/test-vectors.html docs/protocol/wire-format.html \
  docs/robots.txt docs/sitemap.xml; do
  if [ -e "$path" ]; then
    echo "Website source belongs in tenuo-ai/website: $path" >&2
    failed=1
  fi
done

# Do not reintroduce a public-repository Pages deployment under another name.
if grep -En 'uses:.*actions/(configure-pages|jekyll-build-pages|upload-pages-artifact|deploy-pages)@' .github/workflows/*.yml; then
  echo "GitHub Pages deployment belongs in tenuo-ai/website." >&2
  failed=1
fi

exit "$failed"
