# Tenuo documentation

This directory is the user-facing documentation for Tenuo. It is published at
[tenuo.ai](https://tenuo.ai): the [website repository](https://github.com/tenuo-ai/website)
(private) overlays these pages onto the site at build time, and
[`.github/workflows/website.yml`](../.github/workflows/website.yml) asks it to rebuild
whenever `docs/` changes on `main`.

Edit the documentation here. The site's layouts, homepage, blog, legal pages,
`llms.txt` and brand assets live in the website repository, so a page with the
same path must not exist in both places (the website build fails if it does).

- Start with the [Quick Start](quickstart.md), then [Concepts](concepts.md).
- Front matter at the top of each page (`title`, `description`, `og_image` and
  the `guide_*` fields on framework guides) feeds the site's search and social
  metadata. Keep it when editing.
- Links between pages can be relative (`./concepts`); the site resolves them.
