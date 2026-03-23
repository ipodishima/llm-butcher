# LLM-Butcher — Next Steps

## What was built (this session)

### Core
- Claude Code PreToolUse hook that intercepts Bash commands
- **3 check pipelines**: command analysis (90+ patterns), script pre-analysis (17 patterns + recursive fetch up to 3 levels), domain reputation (WHOIS + URLhaus blocklist), typosquat detection (Levenshtein + npm/PyPI registry)
- **Audit logging** to `~/.llm-butcher/audit.log` (JSONL)
- **Config system** with global (`~/.llm-butcher/config.json`) + project (`.llm-butcher.json`) merge
- 159 tests (unit + E2E), 12 demo scenarios, all passing

### Detection patterns cover
- GhostClaw-specific IOCs (dscl, osascript dialogs, persistence paths, env vars)
- Reverse shells (bash, netcat, Perl, Ruby, Python)
- Credential theft (SSH, AWS, GPG, macOS Keychain, browser passwords, dotenv, .netrc, .npmrc, Kubernetes, Docker, Terraform)
- Supply chain (typosquat packages, npm/pip config hijack, CocoaPods repo injection, binary replacement in PATH)
- macOS abuse (TCC.db, tccutil reset, Gatekeeper/SIP disable, quarantine strip, LoginHook, MDM profiles, DYLD injection, proxy hijack)
- Data exfil (clipboard, shell history, env vars, system recon, Apple private data: Notes, Mail, Contacts, Messages, Photos, iPhone backups, Autosave, Finder recent files, Keychain metadata)
- Destructive ops (dd, diskutil, mkfs, killall WindowServer, /etc/hosts poisoning)
- Prompt injection (instruction overrides, fake system messages, suppression directives, false authority claims)
- Camera/mic capture (screencapture, imagesnap, ffmpeg avfoundation)
- Persistence (launchctl, crontab, LaunchAgent plists, shell rc injection, global profile injection, SSH authorized_keys, sudoers backdoor, delayed execution via `at`)
- Chunked/staged exfil (split+upload, tar+curl, rsync/scp to remote)

## Priority fixes for next session

### 1. JSON parse bypass (CRITICAL)

**Problem:** When Claude Code sends a command containing special characters (quotes, backslashes) that break the JSON envelope, our hook can't parse the input and falls through with exit code 1 (warn only). An attacker could exploit this to bypass all checks.

**Examples that bypass:**
- `sqlite3 ~/Library/"TCC.db"` — quotes inside the command break JSON
- Discord token theft with escaped paths
- Commands with complex quoting

**Fix approach:**
- Try multiple parsing strategies (JSON, extract command from partial JSON via regex)
- If parsing truly fails, extract the raw command string and still run pattern matching on it
- Consider: should unparseable input be blocked (exit 2) instead of warned (exit 1)?

### 2. YAML rule packs (REFACTOR)

**Problem:** All 90+ patterns are hardcoded in `commandAnalysis.ts` and `scriptAnalysis.ts`. This makes community contributions require TypeScript knowledge, and the file is getting unwieldy.

**Target format (Nuclei-inspired):**
```yaml
id: ssh-key-theft
name: "Direct access to SSH private keys"
severity: critical
tags: [credentials, ssh, exfiltration]
match:
  mode: regex
  pattern: '~\/\.ssh\/id_'
remediation: "This command reads SSH private keys directly."
```

**Implementation plan:**
1. Create `rules/` directory with rule pack YAML files (core.yaml, macos.yaml, credentials.yaml, network.yaml, prompt-injection.yaml)
2. Add `js-yaml` dependency for parsing
3. Create `src/rules/loader.ts` — loads built-in packs + custom packs from `~/.llm-butcher/rules/` and `.llm-butcher/rules/`
4. Support match modes: `regex`, `keyword`, `keywords_any`, `keywords_all`, `multi_regex` (with `logic: all|any`)
5. Refactor `commandAnalysis.ts` and `scriptAnalysis.ts` to use loaded rules instead of hardcoded arrays
6. Add `--list-rules` CLI flag to show loaded rules
7. Add config option to enable/disable specific rule packs

**Migration:** Extract current patterns from TypeScript into YAML, verify all 159 tests still pass

### 3. SARIF output (v0.2)

GitHub Code Scanning compatible output format. Would let people run LLM-Butcher in CI/CD pipelines.

### 4. AI-powered analysis (v0.3)

Optional deep analysis using Claude/GPT for scripts that pass regex checks but look suspicious (e.g., variable URLs, chained logic, obfuscation beyond our regex patterns). Requires API key.

## Sources & research

- [GhostClaw/GhostLoader — Jamf Threat Labs](https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/)
- [AppleInsider — GhostClaw coverage](https://appleinsider.com/articles/26/03/20/ghostclaw-turns-github-habits-into-a-macos-malware-pipeline)
- [MacGeneration — GhostClaw (FR)](https://www.macg.co/macos/2026/03/ghostclaw-un-malware-qui-exploite-notre-confiance-dans-les-fichiers-readme-307547)
- [Lasso Security — Prompt Injection Defender](https://www.lasso.security/blog/the-hidden-backdoor-in-claude-coding-assistant)
- [fvckgrimm/shellguard](https://github.com/fvckgrimm/shellguard) — Similar project with YAML rules, recursive fetch, AI analysis. Complementary (they don't have domain reputation, typosquat, or command-level scanning)
- [SecureCodeWarrior — Prompt Injection Risks](https://www.securecodewarrior.com/article/prompt-injection-and-the-security-risks-of-agentic-coding-tools)
