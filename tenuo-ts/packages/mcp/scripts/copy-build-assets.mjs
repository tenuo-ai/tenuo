import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const mcpDir = join(dirname(fileURLToPath(import.meta.url)), "..");
copyFileSync(join(mcpDir, "..", "..", "..", "LICENSE"), join(mcpDir, "LICENSE"));
