"""Minimal preview server that renders .md files with the docs dark theme."""
import http.server
import markdown
import os
import re

PORT = 8787
DOCS_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} | Tenuo</title>
<style>
:root {{
  --bg: #0a0a0a; --surface: #111; --surface-2: #1a1a1a;
  --text: #e8e8e8; --text-muted: #888;
  --accent: #00d4ff; --accent-dim: #0099bb;
  --code-bg: #1a1a1a; --border: #2a2a2a;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.7;
}}
.top-nav {{
  position: fixed; top: 0; left: 0; right: 0; height: 56px;
  background: rgba(10,10,10,0.95); backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 24px; z-index: 1000;
}}
.top-nav a {{ color: var(--text-muted); text-decoration: none; font-size: 0.9rem; margin-right: 24px; }}
.top-nav a:hover {{ color: var(--text); }}
.top-nav .brand {{ color: var(--text); font-weight: 600; font-size: 1.1rem; }}
.top-nav .spacer {{ flex: 1; }}
.main {{ max-width: 800px; margin: 0 auto; padding: 88px 24px 64px; }}
h1, h2, h3, h4 {{ font-weight: 600; }}
h1 {{ font-size: 2.2rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--accent); }}
h2 {{ font-size: 1.5rem; margin: 2.5rem 0 1rem; color: var(--accent); }}
h3 {{ font-size: 1.2rem; margin: 2rem 0 0.75rem; }}
p {{ margin: 1rem 0; }}
em {{ color: var(--text-muted); }}
a {{ color: var(--accent); }}
a:hover {{ color: var(--accent-dim); }}
code {{ background: var(--code-bg); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: 'SF Mono','Consolas',monospace; font-size: 0.85em; }}
pre {{ background: var(--code-bg); padding: 1rem; border-radius: 8px; overflow-x: auto; margin: 1rem 0; border: 1px solid var(--border); }}
pre code {{ background: none; padding: 0; font-size: 0.85rem; }}
blockquote {{ border-left: 4px solid var(--accent); padding-left: 1rem; margin: 1rem 0; color: var(--text-muted); }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }}
th, td {{ padding: 0.75rem; border: 1px solid var(--border); text-align: left; }}
th {{ background: var(--surface); }}
ul, ol {{ margin: 1rem 0; padding-left: 2rem; }}
li {{ margin: 0.4rem 0; }}
hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
footer {{ margin-top: 4rem; padding: 2rem 0; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.85rem; text-align: center; }}
footer a {{ color: var(--text-muted); text-decoration: none; }}
</style>
</head>
<body>
<nav class="top-nav">
  <a href="/" class="brand">tenuo</a>
  <span class="spacer"></span>
  <a href="/quickstart">Quick Start</a>
  <a href="/early-access.html">Early Access</a>
  <a href="https://github.com/tenuo-ai/tenuo">GitHub</a>
</nav>
<main class="main">
{content}
<footer>
  <p>&copy; 2026 Tenuo &middot; <a href="/">Home</a> &middot; <a href="/quickstart">Quick Start</a> &middot; <a href="https://github.com/tenuo-ai/tenuo">GitHub</a></p>
</footer>
</main>
</body>
</html>"""


def strip_frontmatter(text):
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            fm = text[3:end]
            title_match = re.search(r'title:\s*["\']?(.+?)["\']?\s*$', fm, re.M)
            title = title_match.group(1) if title_match else "Tenuo"
            return text[end+3:].strip(), title
    return text, "Tenuo"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DOCS_DIR, **kwargs)

    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if path.endswith("/"):
            path += "index"
        candidates = [
            os.path.join(DOCS_DIR, path.lstrip("/") + ".md"),
            os.path.join(DOCS_DIR, path.lstrip("/"), "index.md"),
        ]
        for fpath in candidates:
            if os.path.isfile(fpath):
                with open(fpath) as f:
                    raw = f.read()
                body, title = strip_frontmatter(raw)
                html = markdown.markdown(body, extensions=["tables", "fenced_code"])
                page = TEMPLATE.format(title=title, content=html)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(page.encode())
                return
        super().do_GET()


print(f"Serving docs at http://localhost:{PORT}")
http.server.HTTPServer(("", PORT), Handler).serve_forever()
