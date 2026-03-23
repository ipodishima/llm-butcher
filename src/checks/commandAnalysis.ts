import { Severity, type CheckResult } from "./types.js";

interface CommandPattern {
  regex: RegExp;
  title: string;
  severity: Severity;
  recommendation: string;
}

const COMMAND_PATTERNS: CommandPattern[] = [
  // Reverse shells
  {
    regex: /\/dev\/tcp\/[^\s]+/i,
    title: "Reverse shell via /dev/tcp",
    severity: Severity.CRITICAL,
    recommendation:
      "This command opens a reverse shell connection. Do NOT run it.",
  },
  {
    regex: /\bbash\s+-i\s+>&/i,
    title: "Interactive reverse shell",
    severity: Severity.CRITICAL,
    recommendation:
      "This command opens an interactive reverse shell. Do NOT run it.",
  },
  {
    regex: /\bnc\s+-e\s|ncat\s+-e\s|mkfifo\s/i,
    title: "Reverse shell via netcat/mkfifo",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sets up a reverse shell connection. Do NOT run it.",
  },
  {
    regex: /\bperl\s+-e\s.*socket/i,
    title: "Reverse shell via Perl",
    severity: Severity.CRITICAL,
    recommendation:
      "This command uses Perl to open a network socket — likely a reverse shell. Do NOT run it.",
  },
  {
    regex: /\bruby\s+-rsocket/i,
    title: "Reverse shell via Ruby",
    severity: Severity.CRITICAL,
    recommendation:
      "This command uses Ruby sockets — likely a reverse shell. Do NOT run it.",
  },
  {
    regex: /\bpython3?\s+.*(?:socket\.socket|subprocess.*PIPE.*socket|pty\.spawn)/i,
    title: "Reverse shell via Python",
    severity: Severity.CRITICAL,
    recommendation:
      "This command uses Python sockets — likely a reverse shell. Do NOT run it.",
  },

  // Credential file access
  {
    regex: /~\/\.ssh\/id_|~\/\.ssh\/config|~\/\.ssh\/known_hosts/i,
    title: "Direct access to SSH private keys",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads SSH private keys directly. Verify this is intentional.",
  },
  {
    regex: /~\/\.aws\/credentials|~\/\.aws\/config/i,
    title: "Direct access to AWS credentials",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads AWS credentials directly. Verify this is intentional.",
  },
  {
    regex: /~\/\.gnupg\/|~\/\.gpg/i,
    title: "Direct access to GPG keys",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses GPG private keys. Verify this is intentional.",
  },
  {
    regex: /\/etc\/passwd|\/etc\/shadow/i,
    title: "Access to system credential files",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads system credential files. Do NOT run it.",
  },

  // Data exfiltration via netcat
  {
    regex: /\|\s*nc\s+\S+\s+\d+|\|\s*ncat\s+\S+\s+\d+/i,
    title: "Data piped to remote host via netcat",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sends data to a remote server via netcat. Do NOT run it.",
  },

  // Base64 decode to shell
  {
    regex: /base64\s+(?:-d|--decode|-D)\s*\|?\s*(?:ba)?sh|atob\s*\(.*\)\s*\|\s*(?:ba)?sh/i,
    title: "Base64-decoded payload piped to shell",
    severity: Severity.CRITICAL,
    recommendation:
      "This command decodes a hidden payload and executes it. Do NOT run it.",
  },
  {
    regex: /base64\s+(?:-d|--decode|-D)/i,
    title: "Base64 decoding in command",
    severity: Severity.HIGH,
    recommendation:
      "This command decodes base64 data. Verify the decoded content is safe.",
  },

  // Crypto wallet access
  {
    regex: /wallet\.dat|\.solana\/|\.metamask|\.ethereum/i,
    title: "Cryptocurrency wallet access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses cryptocurrency wallet data. Do NOT run it.",
  },

  // Sensitive directory archival + exfil
  {
    regex: /tar\s+[^\n]*~\/\.ssh/i,
    title: "Archiving SSH directory",
    severity: Severity.CRITICAL,
    recommendation:
      "This command archives your SSH keys. Do NOT run it unless you trust the destination.",
  },
  {
    regex: /tar\s+[^\n]*~\/\.aws/i,
    title: "Archiving AWS credentials directory",
    severity: Severity.CRITICAL,
    recommendation:
      "This command archives your AWS credentials. Do NOT run it.",
  },
  {
    regex: /tar\s+[^\n]*~\/\.gnupg/i,
    title: "Archiving GPG keys directory",
    severity: Severity.CRITICAL,
    recommendation:
      "This command archives your GPG keys. Do NOT run it.",
  },

  // Environment variable exfiltration
  {
    regex: /\b(?:env|printenv|set)\s*\|.*(?:curl|wget|nc\b|ncat\b)/i,
    title: "Environment variables piped to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sends all environment variables (which may contain secrets, tokens, and API keys) to a remote server. Do NOT run it.",
  },

  // macOS Keychain access
  {
    regex: /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)/i,
    title: "macOS Keychain credential extraction",
    severity: Severity.CRITICAL,
    recommendation:
      "This command extracts passwords from the macOS Keychain. Do NOT run it.",
  },
  {
    regex: /sqlite3\s+[^\n]*Keychains/i,
    title: "Direct macOS Keychain database access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads the macOS Keychain database directly. Do NOT run it.",
  },

  // macOS-specific abuse
  {
    regex: /osascript\s+-e\s.*(?:System Events|display\s+dialog|keystroke|key\s+code)/i,
    title: "osascript abuse — system event or dialog manipulation",
    severity: Severity.HIGH,
    recommendation:
      "This command uses osascript to interact with the system. Verify this is expected.",
  },
  {
    regex: /screencapture\s[^\n]*&&\s*curl|screencapture\s[^\n]*\|\s*curl/i,
    title: "Screen capture with exfiltration",
    severity: Severity.CRITICAL,
    recommendation:
      "This command captures your screen and uploads it to a remote server. Do NOT run it.",
  },
  {
    regex: /screencapture\s/i,
    title: "Screen capture command",
    severity: Severity.HIGH,
    recommendation:
      "This command captures your screen. Verify this is expected.",
  },

  // GhostClaw-specific
  {
    regex: /dscl\s+\.\s+-authonly/i,
    title: "macOS credential validation (GhostClaw indicator)",
    severity: Severity.CRITICAL,
    recommendation:
      "This command validates macOS passwords — a known GhostClaw technique. Do NOT run it.",
  },
  {
    regex: /dscl\s+\.\s+-read\s.*AuthenticationAuthority/i,
    title: "macOS authentication data read via dscl",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads macOS authentication data. Do NOT run it.",
  },
  {
    regex: /x-apple\.systempreferences:.*Privacy/i,
    title: "macOS System Preferences manipulation",
    severity: Severity.CRITICAL,
    recommendation:
      "This command tries to modify system privacy settings. Do NOT run it.",
  },

  // macOS defaults write abuse
  {
    regex: /defaults\s+write\s+com\.apple\.loginwindow\s+LoginHook/i,
    title: "macOS LoginHook persistence via defaults write",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sets a LoginHook that runs a script at every login. Do NOT run it.",
  },

  // Network proxy hijack (MITM)
  {
    regex: /networksetup\s+-set(?:web|secureweb|socksfirewall)proxy/i,
    title: "Network proxy hijack (MITM attack)",
    severity: Severity.CRITICAL,
    recommendation:
      "This command changes your network proxy settings, enabling man-in-the-middle attacks. Do NOT run it.",
  },
  {
    regex: /scutil\s+--proxy/i,
    title: "Network proxy configuration read",
    severity: Severity.MEDIUM,
    recommendation:
      "This command reads proxy settings. Verify this is expected.",
  },

  // macOS user plist access
  {
    regex: /\/var\/db\/dslocal\//i,
    title: "Direct macOS user database access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses the macOS local directory service database. Do NOT run it.",
  },

  // Browser data theft
  {
    regex: /Login\s*Data|Cookies\.binarycookies|logins\.json|cookies\.sqlite|signons\.sqlite/i,
    title: "Browser credential or cookie data access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses browser passwords or cookies. Do NOT run it.",
  },
  {
    regex: /Chrome.*(?:Login|Cookies|History)|Firefox.*(?:logins|cookies|places)|Safari.*(?:Cookies|History)/i,
    title: "Browser data directory access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses browser data files. Verify this is expected.",
  },

  // Shell rc file modification (injection)
  {
    regex: />>\s*~\/\.(?:zshrc|bashrc|bash_profile|profile|zprofile)/i,
    title: "Shell profile injection",
    severity: Severity.HIGH,
    recommendation:
      "This command appends to your shell profile. Malware uses this to persist across sessions. Verify the content being added.",
  },

  // Shell profile secret harvesting + exfil
  {
    regex: /(?:cat|grep)\s+[^\n]*~\/\.(?:zshrc|bashrc|bash_profile|profile|zprofile)[^\n]*\|\s*(?:curl|wget|nc\b)/i,
    title: "Shell profile secrets harvested and exfiltrated",
    severity: Severity.CRITICAL,
    recommendation:
      "This command reads your shell profile (which may contain API keys and tokens) and sends it to a remote server. Do NOT run it.",
  },
  {
    regex: /grep\s+[^\n]*(?:TOKEN|SECRET|KEY|PASSWORD|API)[^\n]*\|\s*(?:curl|wget|nc\b)/i,
    title: "Secret/token grep piped to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command searches for secrets and sends them to a remote server. Do NOT run it.",
  },

  // AI/dev tool config exfiltration
  {
    regex: /(?:cat|cp|tar)\s+[^\n]*~\/\.(?:claude|cursor|copilot|config\/anthropic|config\/openai)/i,
    title: "AI tool configuration access",
    severity: Severity.HIGH,
    recommendation:
      "This command reads AI tool configuration files which may contain API keys. Verify this is expected.",
  },

  // LaunchAgent/LaunchDaemon plist writes
  {
    regex: /~\/Library\/LaunchAgents\/|\/Library\/LaunchDaemons\//i,
    title: "LaunchAgent/LaunchDaemon path access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses macOS LaunchAgent/LaunchDaemon paths used for persistence. Verify this is expected.",
  },

  // Persistence
  {
    regex: /launchctl\s+(?:load|submit|enable)|crontab\s/i,
    title: "Persistence mechanism installation",
    severity: Severity.HIGH,
    recommendation:
      "This command installs a persistence mechanism. Verify this is expected.",
  },

  // Insecure downloads
  {
    regex: /curl\s+[^|]*(?:-k|--insecure)\s/i,
    title: "Download with disabled TLS verification",
    severity: Severity.HIGH,
    recommendation:
      "This command disables TLS certificate validation, enabling man-in-the-middle attacks.",
  },

  // ── Round 4: clipboard, history, dotenv, git, dylib, macOS security ──

  // Clipboard exfil/hijack
  {
    regex: /pbpaste\s*\|.*(?:curl|wget|nc\b|ncat\b)/i,
    title: "Clipboard contents exfiltrated to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sends your clipboard (which may contain passwords or tokens) to a remote server. Do NOT run it.",
  },
  {
    regex: /pbcopy\s*<|<<<.*pbcopy|echo\s.*\|\s*pbcopy/i,
    title: "Clipboard hijack",
    severity: Severity.HIGH,
    recommendation:
      "This command overwrites your clipboard. Used in crypto address swap scams. Verify the content.",
  },

  // Shell history exfil
  {
    regex: /(?:history|cat\s+[^\n]*(?:\.zsh_history|\.bash_history|\.history))\s*\|.*(?:curl|wget|nc\b)/i,
    title: "Shell history exfiltrated to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sends your shell history (which contains commands, paths, and possibly secrets) to a remote server. Do NOT run it.",
  },
  {
    regex: /cat\s+[^\n]*(?:\.zsh_history|\.bash_history)/i,
    title: "Shell history file access",
    severity: Severity.HIGH,
    recommendation:
      "This command reads your shell history. Verify this is expected.",
  },

  // dotenv file exfil
  {
    regex: /cat\s+[^\n]*\.env[^\n]*\|.*(?:curl|wget|nc\b)/i,
    title: "dotenv file exfiltrated to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command sends your .env file (containing API keys, DB passwords, secrets) to a remote server. Do NOT run it.",
  },
  {
    regex: /cat\s+[^\n]*\.env(?:\.local|\.production|\.development)?\b/i,
    title: "dotenv file access",
    severity: Severity.MEDIUM,
    recommendation:
      "This command reads a .env file. These typically contain secrets. Verify this is expected.",
  },

  // git remote hijack
  {
    regex: /git\s+remote\s+set-url\s/i,
    title: "Git remote URL modification",
    severity: Severity.HIGH,
    recommendation:
      "This command changes your git remote URL. Could redirect pushes to an attacker's repository. Verify the new URL.",
  },
  {
    regex: /git\s+push\s+--mirror/i,
    title: "Git mirror push (full source code theft)",
    severity: Severity.CRITICAL,
    recommendation:
      "This command mirrors your entire repository to another remote. Do NOT run unless you trust the destination.",
  },

  // dylib injection
  {
    regex: /DYLD_INSERT_LIBRARIES/i,
    title: "macOS dylib injection (DYLD_INSERT_LIBRARIES)",
    severity: Severity.CRITICAL,
    recommendation:
      "This command injects a dynamic library into a process. Used for credential interception and process hijacking. Do NOT run it.",
  },

  // macOS security toggles
  {
    regex: /tccutil\s+reset/i,
    title: "macOS TCC privacy permissions reset",
    severity: Severity.CRITICAL,
    recommendation:
      "This command resets macOS privacy permissions (camera, microphone, disk access). Do NOT run it.",
  },
  {
    regex: /spctl\s+--master-disable/i,
    title: "macOS Gatekeeper disabled",
    severity: Severity.CRITICAL,
    recommendation:
      "This command disables Gatekeeper, allowing unsigned malware to run. Do NOT run it.",
  },
  {
    regex: /csrutil\s+disable/i,
    title: "macOS System Integrity Protection (SIP) disabled",
    severity: Severity.CRITICAL,
    recommendation:
      "This command disables SIP, removing critical system protections. Do NOT run it.",
  },
  {
    regex: /xattr\s+[^\n]*-[rd][^\n]*com\.apple\.quarantine/i,
    title: "macOS quarantine flag stripped",
    severity: Severity.HIGH,
    recommendation:
      "This command removes the quarantine flag from downloaded files, bypassing Gatekeeper warnings.",
  },

  // npm/package manager config hijack
  {
    regex: /npm\s+config\s+set\s+(?:script-shell|prefix|registry)/i,
    title: "npm configuration hijack",
    severity: Severity.CRITICAL,
    recommendation:
      "This command changes npm's configuration. Setting script-shell or registry can redirect all future npm commands through an attacker. Do NOT run it.",
  },
  {
    regex: /pip\s+config\s+set\s+global\.index-url/i,
    title: "pip registry hijack",
    severity: Severity.CRITICAL,
    recommendation:
      "This command changes pip's package index to a potentially malicious registry. Do NOT run it.",
  },

  // Apple private data
  {
    regex: /Messages\/chat\.db/i,
    title: "iMessage database access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses your iMessage database. Do NOT run it.",
  },
  {
    regex: /MobileSync\/Backup|Manifest\.db/i,
    title: "iPhone backup data access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses iPhone backup data. Do NOT run it.",
  },
  {
    regex: /Photos\/Photos Library/i,
    title: "Photos library access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses your Photos library. Verify this is expected.",
  },

  // System recon + exfil
  {
    regex: /(?:system_profiler|sw_vers|ifconfig|networksetup\s+-listallhardwareports)[^\n]*\|\s*(?:curl|wget|nc\b)/i,
    title: "System reconnaissance data exfiltrated",
    severity: Severity.CRITICAL,
    recommendation:
      "This command collects system information and sends it to a remote server. Do NOT run it.",
  },
  {
    regex: /\blog\s+show\s+--predicate[^\n]*\|\s*(?:curl|wget|nc\b)/i,
    title: "macOS unified log exfiltrated",
    severity: Severity.CRITICAL,
    recommendation:
      "This command extracts system logs and sends them to a remote server. Do NOT run it.",
  },

  // ── Prompt injection patterns (from shellguard/nuclei-style rules) ──

  {
    regex: /ignore\s+(?:all\s+)?previous\s+instructions/i,
    title: "Prompt injection: instruction override attempt",
    severity: Severity.CRITICAL,
    recommendation:
      "This content attempts to override AI assistant instructions. Do NOT execute.",
  },
  {
    regex: /\[SYSTEM\]:|<\/?system>|BEGIN\s+SYSTEM\s+PROMPT/i,
    title: "Prompt injection: fake system message",
    severity: Severity.CRITICAL,
    recommendation:
      "This content contains fake system message markers designed to trick AI assistants. Do NOT execute.",
  },
  {
    regex: /do\s+not\s+(?:report|flag|mention|alert|warn)/i,
    title: "Prompt injection: suppression directive",
    severity: Severity.HIGH,
    recommendation:
      "This content tells the AI to hide its findings. Suspicious.",
  },
  {
    regex: /pre-?approved\s+by\s+(?:anthropic|openai|google|microsoft)/i,
    title: "Prompt injection: false authority claim",
    severity: Severity.CRITICAL,
    recommendation:
      "This content falsely claims authorization from an AI provider. Do NOT trust it.",
  },

  // ── Round 5: destructive ops, hosts, MDM, Apple data, binary replacement ──

  // Destructive disk operations
  {
    regex: /\bdd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\//i,
    title: "Destructive disk wipe via dd",
    severity: Severity.CRITICAL,
    recommendation:
      "This command overwrites a disk device with zeros. This destroys all data. Do NOT run it.",
  },
  {
    regex: /diskutil\s+(?:eraseDisk|eraseVolume|partitionDisk)/i,
    title: "Disk erase/format command",
    severity: Severity.CRITICAL,
    recommendation:
      "This command erases or reformats a disk. Do NOT run it.",
  },
  {
    regex: /\bmkfs\./i,
    title: "Filesystem format command",
    severity: Severity.CRITICAL,
    recommendation:
      "This command creates a new filesystem, destroying existing data. Do NOT run it.",
  },

  // /etc/hosts poisoning
  {
    regex: /\/etc\/hosts/i,
    title: "Hosts file modification",
    severity: Severity.CRITICAL,
    recommendation:
      "This command modifies /etc/hosts, which can redirect domain names to attacker-controlled servers. Do NOT run it.",
  },

  // MDM profile install
  {
    regex: /profiles\s+install|\.mobileconfig/i,
    title: "macOS MDM profile installation",
    severity: Severity.CRITICAL,
    recommendation:
      "This command installs a management profile that can give an attacker full control of your device. Do NOT run it.",
  },

  // Apple Notes
  {
    regex: /NoteStore\.sqlite/i,
    title: "Apple Notes database access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses your Apple Notes database. Do NOT run it.",
  },

  // Apple Mail
  {
    regex: /com\.apple\.mail|Mail\/.*\.emlx/i,
    title: "Apple Mail data access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses your email data. Do NOT run it.",
  },

  // Apple Contacts
  {
    regex: /AddressBook.*\.abcddb|Contacts\.sqlite/i,
    title: "Apple Contacts database access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses your contacts database. Do NOT run it.",
  },

  // Critical process killing
  {
    regex: /killall\s+(?:-9\s+)?(?:WindowServer|Dock|SystemUIServer|Finder|loginwindow)/i,
    title: "Critical macOS process kill",
    severity: Severity.CRITICAL,
    recommendation:
      "This command kills critical system processes, crashing your GUI session. Do NOT run it.",
  },

  // Spotlight-assisted recon + exfil
  {
    regex: /mdfind\s+[^\n]*(?:secret|password|token|credential|\.env|\.pem|\.key)[^\n]*\|/i,
    title: "Spotlight search for secrets piped to another command",
    severity: Severity.CRITICAL,
    recommendation:
      "This command uses Spotlight to find sensitive files across your entire disk and pipes the results. Do NOT run it.",
  },

  // Binary replacement (trojan)
  {
    regex: /(?:curl|wget)\s+[^\n]*-o\s*\/usr\/local\/bin\//i,
    title: "Binary replacement in /usr/local/bin",
    severity: Severity.CRITICAL,
    recommendation:
      "This command downloads a file directly into your PATH, potentially replacing a trusted binary (git, node, etc.) with malware. Do NOT run it.",
  },
  {
    regex: /(?:cp|mv)\s+[^\n]*\/usr\/local\/bin\//i,
    title: "File placed in /usr/local/bin",
    severity: Severity.HIGH,
    recommendation:
      "This command places a file in your PATH. Verify the source is trusted.",
  },

  // CocoaPods supply chain
  {
    regex: /pod\s+repo\s+add/i,
    title: "CocoaPods custom repo added",
    severity: Severity.HIGH,
    recommendation:
      "This command adds a custom CocoaPods repo. Malicious repos can inject compromised dependencies. Verify the source.",
  },

  // Home directory bulk archive + exfil
  {
    regex: /(?:tar|zip)\s+[^\n]*~\/(?:Documents|Desktop|Downloads)/i,
    title: "Home directory bulk archive",
    severity: Severity.HIGH,
    recommendation:
      "This command archives personal directories. Verify this is expected and check where the archive is being sent.",
  },

  // Chunked exfil (split + upload)
  {
    regex: /split\s+[^\n]*&&[^\n]*(?:curl|wget)/i,
    title: "Chunked data exfiltration (split + upload)",
    severity: Severity.CRITICAL,
    recommendation:
      "This command splits data into chunks and uploads them — a technique to evade size-based detection. Do NOT run it.",
  },

  // ── Round 6: chat apps, sudoers, SSH keys, cloud creds, TCC, camera ──

  // Chat app token/data theft
  {
    regex: /Application\s*Support\/(?:Slack|discord|Discord|Microsoft\s*Teams|Telegram)/i,
    title: "Chat application data access",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses chat application data (Slack, Discord, Teams, or Telegram). Tokens and messages may be stolen. Do NOT run it.",
  },
  {
    regex: /\.ldb[^\n]*(?:mfa\.|dQw|token)/i,
    title: "Discord token extraction from LevelDB",
    severity: Severity.CRITICAL,
    recommendation:
      "This command searches Discord LevelDB files for authentication tokens. Do NOT run it.",
  },

  // Sudoers/PAM backdoor
  {
    regex: /\/etc\/sudoers/i,
    title: "Sudoers file modification",
    severity: Severity.CRITICAL,
    recommendation:
      "This command modifies sudoers, which can grant passwordless root access to an attacker. Do NOT run it.",
  },
  {
    regex: /\/etc\/pam\.d\//i,
    title: "PAM configuration modification",
    severity: Severity.CRITICAL,
    recommendation:
      "This command modifies PAM authentication modules. Do NOT run it.",
  },

  // SSH authorized_keys injection
  {
    regex: />>?\s*~\/\.ssh\/authorized_keys/i,
    title: "SSH authorized_keys injection",
    severity: Severity.CRITICAL,
    recommendation:
      "This command adds an SSH key to your authorized_keys, granting remote access to your machine. Do NOT run it.",
  },

  // Cloud/DevOps credential files
  {
    regex: /~\/\.kube\/config|KUBECONFIG/i,
    title: "Kubernetes config access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses Kubernetes cluster credentials. Verify this is expected.",
  },
  {
    regex: /~\/\.docker\/config\.json/i,
    title: "Docker registry credentials access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses Docker registry authentication. Verify this is expected.",
  },
  {
    regex: /~\/\.terraform\.d\/credentials|\.tfrc\.json/i,
    title: "Terraform credentials access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses Terraform credentials. Verify this is expected.",
  },
  {
    regex: /~\/\.netrc|\/etc\/netrc/i,
    title: ".netrc credentials access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses .netrc which contains plaintext credentials for remote services. Verify this is expected.",
  },
  {
    regex: /~\/\.npmrc/i,
    title: ".npmrc credentials access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses .npmrc which may contain npm authentication tokens. Verify this is expected.",
  },

  // rsync/scp to remote with sensitive paths
  {
    regex: /(?:rsync|scp)\s+[^\n]*(?:~\/\.ssh|~\/\.aws|~\/\.gnupg|~\/\.kube)[^\n]*@/i,
    title: "Sensitive directories synced to remote host",
    severity: Severity.CRITICAL,
    recommendation:
      "This command copies credential directories to a remote server. Do NOT run it.",
  },

  // TCC.db direct manipulation
  {
    regex: /TCC\.db/i,
    title: "macOS TCC database manipulation",
    severity: Severity.CRITICAL,
    recommendation:
      "This command accesses the TCC privacy database directly, which can grant camera, microphone, or disk access to arbitrary apps. Do NOT run it.",
  },

  // Global profile injection
  {
    regex: />>?\s*\/etc\/(?:profile|zshrc|bashrc|bash\.bashrc)/i,
    title: "Global shell profile injection",
    severity: Severity.CRITICAL,
    recommendation:
      "This command modifies a system-wide shell profile, affecting all users. Do NOT run it.",
  },

  // Camera/mic capture
  {
    regex: /\bimagesnap\b/i,
    title: "Webcam capture via imagesnap",
    severity: Severity.HIGH,
    recommendation:
      "This command captures a photo from your webcam. Verify this is expected.",
  },
  {
    regex: /imagesnap[^\n]*(?:&&|\|)\s*(?:curl|wget|nc\b)/i,
    title: "Webcam capture with exfiltration",
    severity: Severity.CRITICAL,
    recommendation:
      "This command captures a webcam photo and sends it to a remote server. Do NOT run it.",
  },
  {
    regex: /ffmpeg[^\n]*avfoundation/i,
    title: "Audio/video capture via ffmpeg",
    severity: Severity.HIGH,
    recommendation:
      "This command captures audio or video from your camera/microphone. Verify this is expected.",
  },

  // Delayed execution (evade real-time checks)
  {
    regex: /\bat\s+(?:now|midnight|noon|\d)/i,
    title: "Delayed command execution via 'at'",
    severity: Severity.HIGH,
    recommendation:
      "This command schedules execution for later, which can evade real-time security checks. Verify the scheduled command.",
  },

  // Keychain metadata
  {
    regex: /Keychains\/metadata/i,
    title: "macOS Keychain metadata access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses Keychain metadata files. Verify this is expected.",
  },

  // Apple Autosave data
  {
    regex: /Autosave\s*Information/i,
    title: "macOS Autosave data access",
    severity: Severity.HIGH,
    recommendation:
      "This command accesses unsaved document data from across all apps. Verify this is expected.",
  },

  // Finder recent files recon
  {
    regex: /com\.apple\.finder\.plist/i,
    title: "Finder preferences/recent files access",
    severity: Severity.MEDIUM,
    recommendation:
      "This command reads Finder preferences which include recent files and locations.",
  },
];

export function analyzeCommand(command: string): CheckResult[] {
  const results: CheckResult[] = [];

  for (const pattern of COMMAND_PATTERNS) {
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(command)) {
      results.push({
        check: "script-analysis",
        severity: pattern.severity,
        title: pattern.title,
        details: `Dangerous pattern detected in command.`,
        recommendation: pattern.recommendation,
      });
    }
  }

  return results;
}
