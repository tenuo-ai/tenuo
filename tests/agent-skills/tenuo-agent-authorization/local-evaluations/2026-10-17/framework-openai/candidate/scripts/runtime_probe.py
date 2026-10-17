"""Read-only dependency provenance probe; does not call any provider."""
import hashlib
import importlib.metadata as metadata
from pathlib import Path
import sys

import agents
import tenuo
import tenuo.openai
import tenuo_core.tenuo_core as native

print("runtime", sys.version)
print("executable", sys.executable)
for name in ["tenuo", "openai-agents", "openai", "pytest", "pytest-asyncio"]:
    dist = metadata.distribution(name)
    print(name, dist.version, "root", dist.locate_file(""),
          "direct_url", dist.read_text("direct_url.json"))
for module in [tenuo, tenuo.openai, agents, native]:
    path = Path(module.__file__).resolve()
    print("artifact", path, "sha256", hashlib.sha256(path.read_bytes()).hexdigest())
print("tenuo.openai.guard_agent present", hasattr(tenuo.openai, "guard_agent"))
# Validate all installed dependency requirements without requiring pip.
from packaging.requirements import Requirement
failures = []
for dist in metadata.distributions():
    for text in dist.requires or []:
        requirement = Requirement(text)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        try:
            installed = metadata.version(requirement.name)
            if installed not in requirement.specifier:
                failures.append(f"{dist.name}: {text}, installed={installed}")
        except metadata.PackageNotFoundError:
            failures.append(f"{dist.name}: missing {text}")
print("dependency compatibility", failures or "all declared active requirements satisfied")
if failures:
    raise SystemExit(1)
