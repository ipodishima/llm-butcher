import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Insulate tests from the user's real ~/.llm-butcher/config.json — otherwise
// integration tests that assert on default behavior break whenever the
// developer running them has any policy enabled.
const fakeHome = mkdtempSync(join(tmpdir(), "llm-butcher-test-home-"));
process.env.HOME = fakeHome;
process.env.USERPROFILE = fakeHome;

process.on("exit", () => {
  rmSync(fakeHome, { recursive: true, force: true });
});
