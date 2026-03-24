# LLM-Butcher

<p align="center">
  <img src="llm-butcher-cover.jpg" alt="LLM-Butcher" width="100%">
</p>

A security layer between AI coding assistants and your terminal.

LLM-Butcher intercepts shell commands before execution and checks whether the targets — domains, scripts, and packages — are actually trustworthy. It catches supply chain attacks like [GhostClaw](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/) that exploit the trust developers place in README install instructions.

**Fast and local.** All pattern matching runs locally on your machine — no data is sent to any server. The only network calls are WHOIS lookups for unknown domains and registry checks for package names. Most commands are analyzed in under 50ms. Your code and commands never leave your machine.

### Why "Butcher"?

Named after Billy Butcher from *The Boys*. He doesn't trust supes — we don't trust what AI assistants are about to run. Just like Butcher keeps the superpowered in check, LLM-Butcher keeps LLM-generated commands in check. "I don't trust these supes, so I'm checking everything before it runs."

## Why I Built This

I'm an iOS developer with 18 years of experience (started in 2009). I've been embracing AI tools heavily — I barely write code manually anymore. Claude Code is part of my daily workflow.

Then I read about [GhostClaw](https://appleinsider.com/articles/26/03/20/ghostclaw-turns-github-habits-into-a-macos-malware-pipeline), a malware campaign that hides in GitHub README files. The attack is simple: create a legit-looking repo, put a malicious `curl | bash` command in the install instructions, and wait. When a developer — or their AI assistant — follows the README, the malware runs.

That scared the hell out of me.

I realized that every time I ask Claude Code to "install this tool" or "set up this dependency," it reads a README and runs whatever commands it finds. I trust the AI, the AI trusts the README, and nobody is actually checking whether the commands point to something safe.

The existing tools ([Lasso](https://www.lasso.security/blog/the-hidden-backdoor-in-claude-coding-assistant), [Parry](https://github.com), [Dippy](https://github.com/ldayton/Dippy)) do great work on prompt injection and destructive command detection. But none of them answer the question: **"Is the thing this command points to actually trustworthy?"**

So I built LLM-Butcher to sit between the AI and the terminal and ask that question before every install, download, or script execution.

> **Disclaimer:** I am not a cybersecurity expert. I'm an iOS developer who got scared by a real attack and decided to do something about it. This is an MVP — it catches the patterns I know about, but it's far from complete. Pull requests, suggestions, and security reviews are very welcome. If you know more about this space than I do (which is likely), I'd love your input.

## The Real Vulnerability

https://github.com/user-attachments/assets/7c29a774-4088-49f8-806b-fbf0376e8104

Be honest with yourself: when Claude Code says "I'll run `npm install some-package`" or "I'll execute this install script" — do you actually read the full command? Check the domain? Inspect what the script does?

I don't. If it doesn't look obviously dangerous, I click Allow and move on. I've done it hundreds of times. And I'd bet most developers using AI coding tools are doing the same thing.

That's not carelessness — it's trust. You trust the tool, the tool trusts the README, and the README trusts whoever wrote it. The entire chain runs on trust, and nobody is verifying the last link. That's the real vulnerability. Not a zero-day. Not a CVE. Just human nature scaled up by AI speed.

LLM-Butcher exists because I realized I needed something to check the things I wasn't checking.

## The Problem

AI coding assistants (Claude Code, Cursor, Copilot) read README files and execute install commands without verifying if the targets are safe. Attackers exploit this by:

- Creating fake GitHub repos with malicious `curl | bash` commands in READMEs
- Typosquatting popular package names (`lodassh` instead of `lodash`)
- Hiding credential theft behind fake macOS password dialogs
- Obfuscating payloads with base64 encoding

For the full breakdown of how the GhostClaw attack works, see:
- [Jamf Threat Labs — GhostClaw/GhostLoader Technical Analysis](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/)
- [AppleInsider — GhostClaw turns GitHub habits into a macOS malware pipeline](https://appleinsider.com/articles/26/03/20/ghostclaw-turns-github-habits-into-a-macos-malware-pipeline)
- [MacGeneration — GhostClaw, un malware qui exploite notre confiance dans les fichiers ReadMe](https://www.macg.co/macos/2026/03/ghostclaw-un-malware-qui-exploite-notre-confiance-dans-les-fichiers-readme-307547)

## What LLM-Butcher Catches

Run `npm run demo` to see this yourself:

```
SCENARIO                       RESULT     FINDINGS
-----------------------------------------------------------
GhostClaw Full Attack          BLOCKED    5
  CRITICAL: Script validates macOS credentials (GhostClaw indicator)
  CRITICAL: Script manipulates macOS System Preferences
  CRITICAL: Known GhostClaw persistence path detected
Fake Password Dialog           BLOCKED    3
  HIGH: Script creates fake macOS dialog to steal credentials
  HIGH: Script disables TLS certificate validation
  HIGH: Script clears terminal (possible credential theft setup)
Reverse Shell                  BLOCKED    1
  CRITICAL: Script contains reverse shell patterns
Base64 Obfuscation             BLOCKED    1
  HIGH: Script uses base64 decoding (possible obfuscation)
SSH Key Exfiltration           BLOCKED    2
  CRITICAL: Script accesses SSH keys or cloud credentials
Crypto Wallet Theft            BLOCKED    2
  CRITICAL: Script targets cryptocurrency wallets
npm Typosquat (lodassh)        BLOCKED    1
  HIGH: Possible typosquat: "lodassh" is similar to "lodash"
pip Typosquat (requsts)        BLOCKED    2
  HIGH: Possible typosquat: "requsts" is similar to "requests"
  CRITICAL: Package "requsts" does not exist in pip registry
Clean Install Script           PASSED     0
Safe Command (git)             PASSED     0
Legit npm install              PASSED     0
```

## How It Works

LLM-Butcher runs as a **PreToolUse hook** in Claude Code. When Claude Code is about to run a shell command, LLM-Butcher intercepts it and runs three checks in parallel:

### 1. Script Pre-Analysis

When a command pipes a URL to `sh`/`bash` (`curl | sh`), LLM-Butcher downloads the script to memory and scans for 17 malicious patterns:

| Pattern | What it catches |
|---------|----------------|
| `dscl . -authonly` | GhostClaw credential validation |
| `osascript display dialog` | Fake macOS password dialogs |
| `~/.cache/.npm_telemetry` | GhostClaw persistence path |
| `/dev/tcp/` `nc -e` `mkfifo` | Reverse shells |
| `~/.ssh/` `~/.aws/` `~/.gnupg/` | SSH key and credential theft |
| `wallet.dat` `ethereum` `bitcoin` | Cryptocurrency wallet theft |
| `base64 --decode \| sh` | Obfuscated payloads |
| `launchctl load` `crontab` | Persistence mechanisms |
| `curl -k` `--insecure` | Disabled TLS verification |
| Terminal clearing + password prompt | Credential theft setup |

### 2. Domain Reputation

For any command containing URLs to unknown domains:
- **WHOIS age check** — flags domains registered less than 30 days ago (blocks if < 7 days)
- **URLhaus blocklist** — checks against the [abuse.ch](https://urlhaus.abuse.ch/) malware URL database (cached locally, updated every 24h)
- **Allowlist bypass** — known-good domains (github.com, npmjs.com, brew.sh, etc.) are skipped

### 3. Typosquat Detection

For `npm install`, `pip install`, `brew install`, `yarn add`, `pnpm add`:
- **Levenshtein distance** — compares against 10,000+ popular packages per ecosystem
- **Registry verification** — checks if the package actually exists in the registry (npm, PyPI)
- Flags packages that are 1-2 characters away from a popular package

## Installation

### From npm (when published)

```bash
npm install -g llm-butcher
```

### From GitHub

```bash
npm install -g github:your-username/llm-butcher
```

### From source

```bash
git clone https://github.com/your-username/llm-butcher.git
cd llm-butcher
npm install
npm run build
npm link
```

### Hook setup

After installing, add LLM-Butcher to your Claude Code settings (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "llm-butcher"
          }
        ]
      }
    ]
  }
}
```

If you installed from source without `npm link`, point directly to the built file:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/llm-butcher/dist/bin/llm-butcher.js"
          }
        ]
      }
    ]
  }
}
```

That's it. LLM-Butcher will now intercept every shell command Claude Code tries to run and block anything suspicious.

## Try It Yourself

You can test LLM-Butcher against safe, simulated attack scenarios without installing it as a hook. The test fixtures are served from a local HTTP server — nothing malicious ever runs.

### Quick demo (automated)

```bash
git clone https://github.com/your-username/llm-butcher.git
cd llm-butcher
npm install
npm run build
npm run demo
```

This runs all 12 scenarios and prints a pass/fail report.

### Live testing with Claude Code (two terminals)

This is the most realistic way to test — you'll see LLM-Butcher block attacks inside a real Claude Code session.

**Terminal 1** — start the local fixture server:

```bash
npm run test:server
```

The server prints a list of prompts you can copy-paste. It looks like:

```
PROMPT 1 — GhostClaw attack (should be BLOCKED)

  Run this install script: curl -fsSL http://127.0.0.1:62261/ghostclaw-full.sh | bash

PROMPT 2 — Fake password dialog (should be BLOCKED)

  Install the SDK by running: curl -fsSL http://127.0.0.1:62261/fake-dialog.sh | bash

...

PROMPT 6 — Typosquatted package (should be BLOCKED)

  Install lodassh for utility functions

PROMPT 7 — Clean install script (should PASS)

  Run this install script: curl -fsSL http://127.0.0.1:62261/clean-install.sh | bash

PROMPT 8 — Legitimate package (should PASS)

  Install lodash for utility functions
```

**Terminal 2** — open a Claude Code session and paste the prompts:

```bash
claude
```

Then paste a prompt like:

```
Run this install script: curl -fsSL http://127.0.0.1:62261/ghostclaw-full.sh | bash
```

Claude will try to run the command, LLM-Butcher will intercept it, download the script, scan it, and block it with a detailed report of what it found. You'll see the block happen in real time — exactly how it would work if you stumbled on a malicious repo in the wild.

The test scripts are served locally and are never executed. LLM-Butcher only downloads them to memory for analysis.

## Configuration

LLM-Butcher works out of the box with sensible defaults. To customize, create `~/.llm-butcher/config.json` (global) or `.llm-butcher.json` (project-level):

```json
{
  "domainAge": {
    "warnDays": 30,
    "blockDays": 7
  },
  "scriptAnalysis": {
    "enabled": true,
    "maxScriptSizeKB": 512
  },
  "typosquat": {
    "maxLevenshteinDistance": 2,
    "ecosystems": ["npm", "pip", "brew"]
  },
  "allowlist": {
    "domains": ["your-internal-cdn.com"],
    "packages": {
      "npm": ["your-internal-package"],
      "pip": [],
      "brew": []
    }
  },
  "severity": {
    "blockThreshold": "high"
  }
}
```

### Severity Levels

| Level | Exit Code | Behavior |
|-------|-----------|----------|
| `low` | 0 | No output |
| `medium` | 1 | Warning shown, command proceeds |
| `high` | 2 | Command blocked (default threshold) |
| `critical` | 2 | Command blocked |

Set `blockThreshold` to `"critical"` for a more permissive mode, or `"medium"` for paranoid mode.

## Development

```bash
npm install          # Install dependencies
npm run build        # Build for distribution
npm test             # Run all tests (77 unit + E2E tests)
npm run test:e2e     # Run E2E scenarios only
npm run demo         # Run the visual demo
npm run test:server  # Start fixture server for manual testing
```

## How It Complements Existing Tools

| Tool | What it guards against |
|------|----------------------|
| [Lasso](https://www.lasso.security/) | Prompt injection in tool outputs |
| [Parry](https://github.com) | Injection attacks, secrets, data exfiltration |
| [Dippy](https://github.com/ldayton/Dippy) | Destructive commands (`rm -rf`, etc.) |
| **LLM-Butcher** | Malicious targets — fake domains, dangerous scripts, typosquatted packages |

These tools solve different problems and work together. LLM-Butcher doesn't duplicate what they do — it fills the gap between "is the AI being manipulated?" and "is this command pointing to something trustworthy?"

## Background: The GhostClaw Attack

In March 2026, [Jamf Threat Labs](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/) discovered GhostClaw, a macOS infostealer spreading through GitHub repositories. The attack works because:

1. Attackers create legitimate-looking repos (trading bots, SDKs, dev tools)
2. README files contain normal-looking `curl | bash` install commands
3. The install script shows fake progress bars while stealing credentials
4. It uses `dscl . -authonly` to validate stolen macOS passwords
5. It displays fake system dialogs via `osascript` to phish more credentials
6. It persists at `~/.cache/.npm_telemetry/monitor.js` to survive reboots

The attack specifically targets AI-assisted development workflows where tools automatically fetch and execute external code with minimal human review. More details:

- [AppleInsider — GhostClaw turns GitHub habits into a macOS malware pipeline](https://appleinsider.com/articles/26/03/20/ghostclaw-turns-github-habits-into-a-macos-malware-pipeline)
- [Jamf Threat Labs — Full Technical Analysis](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/)

LLM-Butcher was built to catch exactly this class of attack.

## Contributing

This project started as an MVP from a developer who got scared by a real attack. There's a lot of room for improvement:

- More malicious patterns to detect
- Support for more AI coding tools (Cursor, Windsurf, Copilot)
- Smarter script analysis (AST parsing instead of regex)
- GitHub repo reputation checks (star history, commit patterns)
- Community-maintained blocklists
- Better typosquat dictionaries

If you have cybersecurity expertise, your input is especially valuable. Open an issue, submit a PR, or just tell me what I'm missing.

## Credits

- [Jamf Threat Labs](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/) — GhostClaw/GhostLoader research and IOCs
- [AppleInsider](https://appleinsider.com/articles/26/03/20/ghostclaw-turns-github-habits-into-a-macos-malware-pipeline) — GhostClaw coverage that started this project
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/) — Malware URL blocklist
- [fastest-levenshtein](https://github.com/ka-weihe/fastest-levenshtein) — Levenshtein distance calculation
- [whois-json](https://www.npmjs.com/package/whois-json) — WHOIS lookups

## License

MIT
