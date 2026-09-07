#!/usr/bin/env python3
"""Turn the participant guide into the stage-by-stage site under docs/lab/.

    python3 labs/agent-delegation/scripts/guide-to-site.py path/to/participant-guide.md docs/lab

The guide stays the single source of truth; this script is how it reaches
tenuo.ai/lab. It splits on the stage headings, wraps each stage in Jekyll
front matter, and adds a progress strip and previous/next links. Run it again
whenever the guide changes, and commit the output.
"""
import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    sys.exit(__doc__)

guide = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

# Split the guide into top-level sections on "## " headings (and the "# The stages" divider).
parts = re.split(r"\n(?=## |# The stages)", guide)
sections: dict[str, str] = {}
order: list[str] = []
for part in parts:
    m = re.match(r"(##? )(.+)\n", part)
    if not m:
        continue
    title = m.group(2).strip()
    body = part[m.end():].strip("\n")
    body = re.sub(r"\n---\s*$", "", body).strip("\n")
    sections[title] = body
    order.append(title)

def section(prefix: str) -> tuple[str, str]:
    for title in order:
        if title.startswith(prefix):
            return title, sections[title]
    sys.exit(f"section not found: {prefix}")

stage_titles = [t for t in order if re.match(r"Stage \d+:", t)]
STAGES = len([t for t in stage_titles if not t.startswith("Stage 10")])

def slug(n: int) -> str:
    return f"stage-{n}"

def strip_(n: int) -> str:
    cells = []
    for i in range(1, STAGES + 1):
        label = f"**{i}**" if i == n else f"[{i}]({{{{ site.baseurl }}}}/lab/{slug(i)})"
        cells.append(label)
    cells.append("**10**" if n == 10 else f"[10]({{{{ site.baseurl }}}}/lab/stage-10)")
    return "Stages: " + " · ".join(cells)

def nav(prev: str | None, nxt: str | None) -> str:
    left = f"← [{prev[1]}]({{{{ site.baseurl }}}}/lab/{prev[0]})" if prev else ""
    right = f"[{nxt[1]}]({{{{ site.baseurl }}}}/lab/{nxt[0]}) →" if nxt else ""
    return f"{left}{'   |   ' if left and right else ''}{right}"

def page(name: str, title: str, description: str, body: str) -> None:
    (out / f"{name}.md").write_text(
        f"---\ntitle: \"{title}\"\ndescription: \"{description}\"\n---\n\n{body.strip()}\n"
    )

# ---- index: everything before the stages
intro_titles = [t for t in order if order.index(t) < order.index(stage_titles[0]) and t != "The stages" and not t.startswith("Participant guide")]
head = guide.split("\n## ", 1)[0]
head = re.sub(r"^# .*\n## .*\n", "", head).strip()
index = [head if head.startswith("# ") else "# AI Agent Delegation Challenge\n\n" + head, ""]
for t in intro_titles:
    index += [f"## {t}", "", sections[t], ""]
index += ["## The stages", "", sections.get("The stages", ""), "", strip_(0), "", f"Start with [{stage_titles[0]}]({{{{ site.baseurl }}}}/lab/stage-1) →"]
page("index", "Agent Delegation Challenge", "A ninety-minute lab: six AI agents, one rogue, nine stages. Secure the system so the trip still happens.", "\n".join(index))

# ---- one page per stage
for i, title in enumerate(stage_titles):
    n = int(re.match(r"Stage (\d+)", title).group(1))
    prev = (slug(n - 1), stage_titles[i - 1]) if i > 0 else ("index", "Setup")
    nxt = (slug(n + 1), stage_titles[i + 1]) if i + 1 < len(stage_titles) else None
    body = "\n".join([strip_(n), "", f"# {title}", "", sections[title], "", nav(prev, nxt)])
    if n == STAGES:
        stuck = section("When you're stuck")
        learned = section("What you just learned")
        further = section("Going further")
        body = "\n".join([strip_(n), "", f"# {title}", "", sections[title], "", f"## {stuck[0]}", "", stuck[1], "", f"## {learned[0]}", "", learned[1], "", f"## {further[0]}", "", further[1], "", nav(prev, nxt)])
    page(slug(n), title, f"Stage {n} of the Agent Delegation Challenge.", body)

print(f"wrote {out}/index.md and {len(stage_titles)} stage pages")
