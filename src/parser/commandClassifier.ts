import type { CommandClassification, PackageInstall } from "../checks/types.js";
import { extractUrls } from "./urlExtractor.js";

const PIPE_TO_SHELL_REGEX =
  /\|\s*(sudo\s+)?(ba)?sh\b|\|\s*(sudo\s+)?zsh\b|\|\s*(sudo\s+)?python3?\b/i;

const CURL_WGET_URL_PIPE =
  /(?:curl|wget)\s+[^|]*?(https?:\/\/[^\s"'<>|;)}\]]+)[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh/i;

const PACKAGE_INSTALL_PATTERNS: {
  regex: RegExp;
  manager: PackageInstall["manager"];
}[] = [
  {
    regex: /(?<![a-z])npm\s+(?:install|i|add)\s+(?:-[gGDS]\s+)*([a-z@][a-z0-9._\-/@]*)/gi,
    manager: "npm",
  },
  {
    regex: /yarn\s+add\s+(?:--dev\s+)?([a-z@][a-z0-9._\-/@]*)/gi,
    manager: "yarn",
  },
  {
    regex: /pnpm\s+(?:add|install)\s+(?:-[gGD]\s+)?([a-z@][a-z0-9._\-/@]*)/gi,
    manager: "pnpm",
  },
  {
    regex: /pip3?\s+install\s+(?:--user\s+)?([a-zA-Z][a-zA-Z0-9._-]*)/gi,
    manager: "pip",
  },
  {
    regex: /brew\s+install\s+(?:--cask\s+)?([a-z][a-z0-9._\-/]*)/gi,
    manager: "brew",
  },
];

export function classifyCommand(command: string): CommandClassification {
  const urls = extractUrls(command);
  const pipesToShell = PIPE_TO_SHELL_REGEX.test(command);

  // Extract the URL being piped to shell
  let pipeToShellUrl: string | null = null;
  if (pipesToShell) {
    const match = command.match(CURL_WGET_URL_PIPE);
    if (match?.[1]) {
      pipeToShellUrl = match[1];
    }
  }

  // Extract package installs
  const packageInstalls: PackageInstall[] = [];
  for (const { regex, manager } of PACKAGE_INSTALL_PATTERNS) {
    // Reset regex state
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(command)) !== null) {
      const name = match[1];
      // Skip flags and empty names
      if (name && !name.startsWith("-")) {
        packageInstalls.push({ manager, name });
      }
    }
  }

  return {
    urls,
    pipesToShell,
    packageInstalls,
    pipeToShellUrl,
  };
}
