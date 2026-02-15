# Windows Security Toolkit

A collection of PowerShell scripts for Windows security analysis, incident response, and supply-chain threat detection.

## Scripts

### npm-security-audit.ps1

Comprehensive npm supply chain security audit. Detects malicious package behavior, obfuscated payloads, credential theft indicators, and suspicious network activity. Originally developed to investigate the AICryptoTracker stealer supply-chain attack, now generalized for detecting similar threats.

**What it checks:**
- Stealer package build artifacts on disk
- npm install logs for evidence of package download/compilation
- Package manifest tampering and suspicious dependencies
- Browser credential database access times and copies in temp directories
- Outbound network connections to C2 servers
- Exposed secrets in `.env` files
- Windows Defender detection history
- SSH keys and Git credentials
- PowerShell script block logs and Sysmon events
- Firewall rule tampering

```powershell
.\npm-security-audit.ps1
```

---

### pre-repo-scan.ps1

Pre-clone / pre-install repository security scanner. Run this **before** `npm install`, `pip install`, or any build commands to detect supply-chain threats embedded in a repository.

**What it checks:**
- `.vscode/tasks.json` auto-run and curl-pipe-to-shell attacks
- `.vscode/settings.json` terminal injection / shellArgs
- Malicious VS Code extension recommendations
- Obfuscated JavaScript in config files
- Suspicious npm lifecycle scripts (`preinstall`, `postinstall`)
- Known malicious npm packages (extensible list)
- Hidden scripts in Makefile / Dockerfile / CI configs
- Binary / executable files that shouldn't be in a source repo
- Encoded or obfuscated PowerShell / shell commands
- Large or obfuscated config files (postcss, tailwind, vite, webpack, etc.)

Returns exit code `1` if any **CRITICAL** findings are detected (suitable for CI gates).

```powershell
# Scan current directory
.\pre-repo-scan.ps1

# Scan a specific repo
.\pre-repo-scan.ps1 -RepoDir C:\repos\suspicious-project

# Add custom known-bad packages
.\pre-repo-scan.ps1 -KnownBadPackages @('evil-pkg','malware-lib')
```

---

### forensic-triage.ps1

General-purpose Windows forensic triage and incident response script. Performs an in-depth investigation across multiple evidence categories and exports structured JSON reports with SHA-256 hashes for chain-of-custody integrity.

**Evidence categories:**
- Process analysis (running processes, suspicious command lines, DLL injection)
- Network forensics (active connections, DNS cache, firewall rules, BITS jobs)
- Persistence mechanisms (registry Run keys, startup folder, scheduled tasks, services, WMI subscriptions)
- File system forensics (recent files, Prefetch, USN journal, Amcache, Shimcache)
- Browser forensics (credential DBs, history, cookies)
- Credential stores (SSH keys, Git tokens, npm tokens, environment files, crypto wallets)
- Event log analysis (Security, Sysmon, PowerShell ScriptBlock, Defender, WFP)
- User activity analysis (RecentDocs, RDP sessions, PowerShell command history)
- Windows Defender detections and quarantine

```powershell
# Basic triage (last 7 days)
.\forensic-triage.ps1

# Custom IOC patterns and extended lookback
.\forensic-triage.ps1 -IOCPatterns @('malware\.exe','evil\.dll','c2server\.com') -DaysBack 14

# Full investigation with hashing and extended event logs
.\forensic-triage.ps1 -OutputDir C:\Evidence\Case001 -CollectHashes -IncludeFullEventLogs
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Administrator privileges (recommended for full forensic access)

## Disclaimer

These scripts are provided for **defensive security and incident response purposes only**. Use responsibly and in accordance with applicable laws and organizational policies.
