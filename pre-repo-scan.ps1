<#
.SYNOPSIS
    Pre-clone / pre-install repository security scanner.

.DESCRIPTION
    Scans a repository directory for common malware indicators BEFORE running
    npm install, pip install, or any build commands. Covers:

      1.  .vscode/tasks.json auto-run + curl-pipe-to-shell
      2.  .vscode/settings.json terminal injection / shellArgs
      3.  .vscode/extensions.json malicious extension recommendations
      4.  Obfuscated JavaScript in config files
      5.  Suspicious npm lifecycle scripts (preinstall, postinstall, install)
      6.  Known malicious npm packages (extensible list)
      7.  Suspicious dependencies (credential theft toolkits)
      8.  Hidden scripts in Makefile / Dockerfile / CI configs
      9.  Binary / executable files that shouldn't be in a source repo
     10.  Encoded or obfuscated PowerShell / shell commands
     11.  Suspicious .env or secret files committed to repo
     12.  Large / obfuscated config files (postcss, tailwind, vite, webpack, etc.)

    Returns exit code 1 if any CRITICAL findings are detected (suitable for CI gates).

.PARAMETER RepoDir
    Path to the repository directory to scan. Default: current directory.

.PARAMETER KnownBadPackages
    Array of known malicious package name patterns (regex). Extensible.

.PARAMETER MaxConfigSizeChars
    Config files larger than this are flagged as potentially containing payloads. Default: 1000.

.EXAMPLE
    .\pre-repo-scan.ps1

.EXAMPLE
    .\pre-repo-scan.ps1 -RepoDir C:\repos\suspicious-project

.EXAMPLE
    .\pre-repo-scan.ps1 -KnownBadPackages @('evil-pkg','malware-lib','trojan-dep')
#>

[CmdletBinding()]
param(
    [string]$RepoDir = ".",

    [string[]]$KnownBadPackages = @(
        'react-svg-helper-fast',
        'rest-icon-moduler',
        'vue-helper-auth',
        'node-hide-console-windows',
        'bettersqlite3',
        'better-sqlite3-helper',
        'event-stream',
        'ua-parser-js',
        'coa',
        'rc',
        'colors',
        'faker'
    ),

    [int]$MaxConfigSizeChars = 1000
)

$ErrorActionPreference = 'SilentlyContinue'
$findings = @()
$criticalCount = 0
$warningCount = 0

function Add-ScanFinding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO')]
        [string]$Severity,
        [string]$Check,
        [string]$Message,
        [string]$File = $null,
        [string]$Detail = $null
    )
    $color = switch ($Severity) {
        'CRITICAL' { 'Red' }
        'WARNING'  { 'DarkYellow' }
        'INFO'     { 'Gray' }
    }
    $script:findings += [ordered]@{
        Severity = $Severity
        Check    = $Check
        Message  = $Message
        File     = $File
        Detail   = $Detail
    }
    if ($Severity -eq 'CRITICAL') { $script:criticalCount++ }
    if ($Severity -eq 'WARNING')  { $script:warningCount++ }

    $prefix = "  [$Severity]"
    $text = if ($File) { "$Message -> $File" } else { $Message }
    Write-Host $prefix $text -ForegroundColor $color
    if ($Detail) { Write-Host "           $Detail" -ForegroundColor Gray }
}

$RepoDir = Resolve-Path $RepoDir -ErrorAction Stop

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PRE-REPO SECURITY SCAN" -ForegroundColor Cyan
Write-Host "  Target: $RepoDir" -ForegroundColor Cyan
Write-Host "  $(Get-Date)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Scanning for malware indicators BEFORE npm install / build..." -ForegroundColor White
Write-Host ""

# ============================================================
# 1. .vscode/tasks.json - Auto-run + curl-pipe-to-shell
# ============================================================
Write-Host "=== [1] .vscode/tasks.json - AUTO-RUN & CURL PIPES ===" -ForegroundColor Yellow
$tasksFiles = Get-ChildItem -Path $RepoDir -Recurse -Filter "tasks.json" -File |
    Where-Object { $_.FullName -match '[/\\]\.vscode[/\\]' }
foreach ($tf in $tasksFiles) {
    $content = Get-Content $tf.FullName -Raw
    if ($content -match 'runOn.*folderOpen|folderOpen.*runOn') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'tasks.json' `
            -Message "tasks.json auto-runs on folder open" -File $tf.FullName
    }
    if ($content -match 'curl.*\|.*(bash|sh|cmd|powershell|pwsh|node)|wget.*\|.*(bash|sh|cmd)') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'tasks.json' `
            -Message "tasks.json contains curl/wget pipe-to-shell" -File $tf.FullName
    }
    if ($content -match 'Invoke-WebRequest|Invoke-RestMethod|IEX|Invoke-Expression|DownloadString|DownloadFile|Start-BitsTransfer') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'tasks.json' `
            -Message "tasks.json contains PowerShell download/exec commands" -File $tf.FullName
    }
    if (-not ($content -match 'runOn|curl|wget|Invoke-')) {
        Write-Host "  OK: $($tf.FullName)" -ForegroundColor Green
    }
}
if (-not $tasksFiles) { Write-Host "  No .vscode/tasks.json found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 2. .vscode/settings.json - Terminal injection / shellArgs
# ============================================================
Write-Host "=== [2] .vscode/settings.json - TERMINAL INJECTION ===" -ForegroundColor Yellow
$settingsFiles = Get-ChildItem -Path $RepoDir -Recurse -Filter "settings.json" -File |
    Where-Object { $_.FullName -match '[/\\]\.vscode[/\\]' }
foreach ($sf in $settingsFiles) {
    $content = Get-Content $sf.FullName -Raw
    if ($content -match 'terminal\.integrated\.shellArgs|terminal\.integrated\.defaultProfile|terminal\.integrated\.automationShell') {
        Add-ScanFinding -Severity 'WARNING' -Check 'settings.json' `
            -Message "settings.json modifies terminal shell configuration" -File $sf.FullName
    }
    if ($content -match 'terminal\.integrated\.env\.|terminal\.integrated\.profiles') {
        Add-ScanFinding -Severity 'WARNING' -Check 'settings.json' `
            -Message "settings.json sets terminal environment variables or profiles" -File $sf.FullName
    }
    if ($content -match '-enc|-EncodedCommand|curl|wget|Invoke-WebRequest|IEX') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'settings.json' `
            -Message "settings.json contains encoded commands or download instructions" -File $sf.FullName
    }
    if (-not ($content -match 'terminal\.integrated|enc|curl|wget|Invoke-')) {
        Write-Host "  OK: $($sf.FullName)" -ForegroundColor Green
    }
}
if (-not $settingsFiles) { Write-Host "  No .vscode/settings.json found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 3. .vscode/extensions.json - Malicious extension recommendations
# ============================================================
Write-Host "=== [3] .vscode/extensions.json - EXTENSION RECOMMENDATIONS ===" -ForegroundColor Yellow
$extFiles = Get-ChildItem -Path $RepoDir -Recurse -Filter "extensions.json" -File |
    Where-Object { $_.FullName -match '[/\\]\.vscode[/\\]' }
foreach ($ef in $extFiles) {
    $content = Get-Content $ef.FullName -Raw
    # Flag extensions that aren't from well-known publishers
    if ($content -match 'recommendations') {
        Write-Host "  Recommended extensions found in $($ef.FullName):" -ForegroundColor DarkYellow
        try {
            $extJson = $content | ConvertFrom-Json
            foreach ($ext in $extJson.recommendations) {
                $publisher = ($ext -split '\.')[0]
                $knownPublishers = @('ms-python','ms-vscode','ms-dotnettools','dbaeumer','esbenp','redhat','golang',
                                     'ms-azuretools','github','microsoft','eamodio','bradlc','formulahendry',
                                     'christian-kohler','pkief','ritwickdey','vscode-icons-team','ms-toolsai',
                                     'ms-ceintl','ms-playwright','streetsidesoftware','yzhang')
                if ($publisher -notin $knownPublishers) {
                    Add-ScanFinding -Severity 'WARNING' -Check 'extensions.json' `
                        -Message "Unknown extension publisher: $ext" -File $ef.FullName `
                        -Detail "Verify this extension is legitimate before installing"
                }
            }
        } catch {
            Write-Host "  Could not parse extensions.json" -ForegroundColor Gray
        }
    }
}
if (-not $extFiles) { Write-Host "  No .vscode/extensions.json found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 4. Obfuscated JavaScript in config files
# ============================================================
Write-Host "=== [4] OBFUSCATED JS IN CONFIG FILES ===" -ForegroundColor Yellow
$configPatterns = @('*.config.js','*.config.ts','*.config.mjs','*.config.cjs',
                    'postcss.config.*','tailwind.config.*','vite.config.*','webpack.config.*',
                    'rollup.config.*','babel.config.*','jest.config.*','next.config.*',
                    'nuxt.config.*','svelte.config.*','.babelrc','.eslintrc.js','gulpfile.js','Gruntfile.js')
$obfuscationPatterns = 'fromCharCode|\\x[0-9a-fA-F]{2}|eval\s*\(|new\s+Function\s*\(|atob\s*\(|Buffer\.from.*base64|_0x[a-f0-9]{4}|\\u00[0-9a-f]{2}'

$configFiles = @()
foreach ($pattern in $configPatterns) {
    $configFiles += Get-ChildItem -Path $RepoDir -Recurse -Filter $pattern -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch 'node_modules|\.git[/\\]|dist[/\\]|build[/\\]' }
}
$configFiles = $configFiles | Sort-Object FullName -Unique

foreach ($cf in $configFiles) {
    $content = Get-Content $cf.FullName -Raw
    $fileLen = $content.Length

    # Check for obfuscation patterns
    if ($content -match $obfuscationPatterns) {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'Obfuscation' `
            -Message "Obfuscation patterns detected ($fileLen chars)" -File $cf.FullName `
            -Detail ([regex]::Matches($content, $obfuscationPatterns) | Select-Object -First 3 | ForEach-Object { $_.Value }) -join ', '
    }

    # Check for suspiciously large configs
    if ($fileLen -gt $MaxConfigSizeChars) {
        Add-ScanFinding -Severity 'WARNING' -Check 'ConfigSize' `
            -Message "Config file is $fileLen chars (threshold: $MaxConfigSizeChars)" -File $cf.FullName `
            -Detail "Large config files may contain hidden payloads"
    }
}
if ($configFiles.Count -eq 0) { Write-Host "  No config files found to scan." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 5. package.json - Suspicious lifecycle scripts
# ============================================================
Write-Host "=== [5] PACKAGE.JSON - LIFECYCLE SCRIPTS ===" -ForegroundColor Yellow
$packageFiles = Get-ChildItem -Path $RepoDir -Recurse -Filter "package.json" -File |
    Where-Object { $_.FullName -notmatch 'node_modules' }
foreach ($pf in $packageFiles) {
    try {
        $pkgJson = Get-Content $pf.FullName -Raw | ConvertFrom-Json
        $scripts = $pkgJson.scripts
        if ($scripts) {
            $dangerousHooks = @('preinstall','postinstall','install','preuninstall','postuninstall',
                                'prepublish','preprepare','postprepare','prepare')
            foreach ($hook in $dangerousHooks) {
                $scriptVal = $scripts.$hook
                if ($scriptVal) {
                    $severity = 'WARNING'
                    # Escalate if the script downloads or executes remote code
                    if ($scriptVal -match 'curl|wget|node\s+-e|powershell|bash\s+-c|sh\s+-c|Invoke-|http://|https://') {
                        $severity = 'CRITICAL'
                    }
                    Add-ScanFinding -Severity $severity -Check 'LifecycleScript' `
                        -Message "Lifecycle hook '$hook' found" -File $pf.FullName `
                        -Detail $scriptVal
                }
            }
        }
    } catch {
        Write-Host "  Could not parse $($pf.FullName)" -ForegroundColor Gray
    }
}
if (-not $packageFiles) { Write-Host "  No package.json found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 6. Known malicious packages
# ============================================================
Write-Host "=== [6] KNOWN MALICIOUS PACKAGES ===" -ForegroundColor Yellow
$badPkgRegex = ($KnownBadPackages | ForEach-Object { [regex]::Escape($_) }) -join '|'
foreach ($pf in $packageFiles) {
    $content = Get-Content $pf.FullName -Raw
    $matches = [regex]::Matches($content, $badPkgRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'MaliciousPackage' `
            -Message "Known malicious package detected: $($m.Value)" -File $pf.FullName
    }
    if ($matches.Count -eq 0) {
        Write-Host "  OK: No known bad packages in $($pf.FullName)" -ForegroundColor Green
    }
}

# Also check lockfiles
$lockFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object { $_.Name -match '^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$' -and $_.FullName -notmatch 'node_modules' }
foreach ($lf in $lockFiles) {
    $content = Get-Content $lf.FullName -Raw
    $matches = [regex]::Matches($content, $badPkgRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'MaliciousPackage' `
            -Message "Known malicious package in lockfile: $($m.Value)" -File $lf.FullName
    }
}
Write-Host ""

# ============================================================
# 7. Suspicious dependencies (credential theft toolkits)
# ============================================================
Write-Host "=== [7] SUSPICIOUS DEPENDENCY COMBINATIONS ===" -ForegroundColor Yellow
foreach ($pf in $packageFiles) {
    try {
        $pkgJson = Get-Content $pf.FullName -Raw | ConvertFrom-Json
        $allDeps = @()
        if ($pkgJson.dependencies) {
            $allDeps += $pkgJson.dependencies.PSObject.Properties.Name
        }
        if ($pkgJson.devDependencies) {
            $allDeps += $pkgJson.devDependencies.PSObject.Properties.Name
        }

        # Flag suspicious combination of deps that together form a stealer toolkit
        $hasDpapi = $allDeps | Where-Object { $_ -match 'dpapi|@primno' }
        $hasSqlite = $allDeps | Where-Object { $_ -match 'better-sqlite3|sql\.js|sqlite3' }
        $hasExfil = $allDeps | Where-Object { $_ -match 'socket\.io-client|ws|axios|node-fetch|got|request' }
        $hasMachineId = $allDeps | Where-Object { $_ -match 'node-machine-id|systeminformation' }

        if ($hasDpapi -and $hasSqlite) {
            Add-ScanFinding -Severity 'CRITICAL' -Check 'SuspiciousDeps' `
                -Message "DPAPI + SQLite dependencies = credential stealer toolkit" -File $pf.FullName `
                -Detail "DPAPI: $hasDpapi | SQLite: $hasSqlite"
        }
        if ($hasDpapi -and $hasExfil) {
            Add-ScanFinding -Severity 'CRITICAL' -Check 'SuspiciousDeps' `
                -Message "DPAPI + network exfiltration dependencies detected" -File $pf.FullName `
                -Detail "DPAPI: $hasDpapi | Network: $hasExfil"
        }
        if ($hasMachineId) {
            Add-ScanFinding -Severity 'WARNING' -Check 'SuspiciousDeps' `
                -Message "Machine fingerprinting dependency found" -File $pf.FullName `
                -Detail "$hasMachineId"
        }
    } catch {}
}
if (-not $packageFiles) { Write-Host "  No package.json to analyze." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 8. Makefile / Dockerfile / CI configs
# ============================================================
Write-Host "=== [8] MAKEFILE / DOCKERFILE / CI CONFIGS ===" -ForegroundColor Yellow
$buildFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object {
        $_.Name -match '^(Makefile|Dockerfile|docker-compose\.ya?ml|Jenkinsfile|Vagrantfile)$' -or
        $_.FullName -match '[/\\]\.github[/\\]workflows[/\\].*\.ya?ml$' -or
        $_.FullName -match '[/\\]\.gitlab-ci\.yml$' -or
        $_.FullName -match '[/\\]\.circleci[/\\]' -or
        $_.FullName -match '[/\\]\.travis\.yml$'
    } |
    Where-Object { $_.FullName -notmatch 'node_modules|\.git[/\\]' }

foreach ($bf in $buildFiles) {
    $content = Get-Content $bf.FullName -Raw
    if ($content -match 'curl.*\|.*(bash|sh)|wget.*\|.*(bash|sh)|curl.*-o\s+/tmp|Invoke-WebRequest.*IEX|DownloadString') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'BuildFile' `
            -Message "Remote code execution pattern found" -File $bf.FullName
    }
    if ($content -match 'base64\s+-d|base64\s+--decode|-EncodedCommand|-enc\s') {
        Add-ScanFinding -Severity 'WARNING' -Check 'BuildFile' `
            -Message "Base64 encoded commands detected" -File $bf.FullName
    }
    if ($content -match 'chmod\s+\+x.*&&.*\.\/|chmod\s+777') {
        Add-ScanFinding -Severity 'WARNING' -Check 'BuildFile' `
            -Message "Executable permission change + execution pattern" -File $bf.FullName
    }
}
if ($buildFiles.Count -eq 0) { Write-Host "  No build/CI config files found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 9. Binary / executable files in repo
# ============================================================
Write-Host "=== [9] BINARY / EXECUTABLE FILES IN REPO ===" -ForegroundColor Yellow
$binaryExts = @('.exe','.dll','.scr','.com','.bat','.cmd','.msi','.pif',
                '.hta','.vbs','.vbe','.jse','.wsf','.wsh','.ps1','.psm1',
                '.so','.dylib','.elf','.bin','.dat')
$binaryFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object {
        $_.Extension -in $binaryExts -and
        $_.FullName -notmatch 'node_modules|\.git[/\\]|dist[/\\]|build[/\\]|__pycache__'
    }
foreach ($bf in $binaryFiles) {
    $severity = if ($bf.Extension -in @('.exe','.dll','.scr','.com','.msi','.pif','.hta')) { 'CRITICAL' } else { 'WARNING' }
    Add-ScanFinding -Severity $severity -Check 'BinaryFile' `
        -Message "Binary/executable file in repo: $($bf.Name) ($($bf.Length) bytes)" -File $bf.FullName
}
if ($binaryFiles.Count -eq 0) { Write-Host "  No suspicious binary files found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 10. Encoded / obfuscated shell commands in any file
# ============================================================
Write-Host "=== [10] ENCODED / OBFUSCATED COMMANDS ===" -ForegroundColor Yellow
$sourceFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object {
        $_.Extension -match '\.(js|ts|jsx|tsx|mjs|cjs|py|rb|sh|bash|ps1|psm1|psd1|yml|yaml|json|toml|cfg|ini|xml)$' -and
        $_.FullName -notmatch 'node_modules|\.git[/\\]|dist[/\\]|build[/\\]|__pycache__|\.lock$' -and
        $_.Length -lt 5MB  # Skip very large files
    }

$encodedPatterns = 'powershell.*-enc|powershell.*-EncodedCommand|certutil.*-encode|certutil.*-urlcache|bitsadmin\s+/transfer|mshta\s+(http|javascript)|regsvr32\s+/s\s+/u.*scrobj|rundll32.*javascript'
$encodedFindings = 0
foreach ($sf in $sourceFiles) {
    try {
        $content = [System.IO.File]::ReadAllText($sf.FullName)
        if ($content -match $encodedPatterns) {
            Add-ScanFinding -Severity 'CRITICAL' -Check 'EncodedCommand' `
                -Message "Encoded/LOLBin command pattern detected" -File $sf.FullName
            $encodedFindings++
        }
    } catch {}
}
if ($encodedFindings -eq 0) { Write-Host "  No encoded command patterns found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 11. Suspicious .env / secret files
# ============================================================
Write-Host "=== [11] COMMITTED .ENV / SECRET FILES ===" -ForegroundColor Yellow
$secretFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object {
        $_.Name -match '^\.env(\..*)?$|^\.secret|^credentials|^\.aws[/\\]|^\.gcp[/\\]|id_rsa$|id_ed25519$|\.pem$|\.key$|\.pfx$|\.p12$' -and
        $_.FullName -notmatch 'node_modules|\.git[/\\]|\.env\.example|\.env\.template|\.env\.sample'
    }
foreach ($sf in $secretFiles) {
    Add-ScanFinding -Severity 'WARNING' -Check 'SecretFile' `
        -Message "Potential secret/credential file committed to repo" -File $sf.FullName
}
if ($secretFiles.Count -eq 0) { Write-Host "  No secret files found in repo." -ForegroundColor Green }
Write-Host ""

# ============================================================
# 12. Python-specific checks (setup.py, requirements.txt)
# ============================================================
Write-Host "=== [12] PYTHON PROJECT CHECKS ===" -ForegroundColor Yellow
$setupFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object { $_.Name -match '^(setup\.py|setup\.cfg|pyproject\.toml)$' -and $_.FullName -notmatch 'node_modules|\.git[/\\]' }
foreach ($sf in $setupFiles) {
    $content = Get-Content $sf.FullName -Raw
    if ($content -match 'os\.system|subprocess\.(call|run|Popen)|exec\s*\(|eval\s*\(|__import__.*os|urllib\.request') {
        Add-ScanFinding -Severity 'CRITICAL' -Check 'PythonSetup' `
            -Message "Code execution in setup file" -File $sf.FullName
    }
}

$reqFiles = Get-ChildItem -Path $RepoDir -Recurse -File |
    Where-Object { $_.Name -match '^requirements.*\.txt$' -and $_.FullName -notmatch 'node_modules|\.git[/\\]' }
foreach ($rf in $reqFiles) {
    $content = Get-Content $rf.FullName -Raw
    # Check for packages installed from URLs or git repos
    if ($content -match 'http://|https://.*\.git|git\+') {
        Add-ScanFinding -Severity 'WARNING' -Check 'PythonDeps' `
            -Message "Requirements installed from URL/Git (verify source)" -File $rf.FullName
    }
}
if ($setupFiles.Count -eq 0 -and $reqFiles.Count -eq 0) { Write-Host "  No Python project files found." -ForegroundColor Green }
Write-Host ""

# ============================================================
# SUMMARY
# ============================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$totalFindings = $findings.Count
if ($totalFindings -eq 0) {
    Write-Host "  No suspicious indicators found." -ForegroundColor Green
    Write-Host "  This does NOT guarantee the repo is safe - review code manually." -ForegroundColor Gray
} else {
    $color = if ($criticalCount -gt 0) { 'Red' } else { 'DarkYellow' }
    Write-Host "  Total findings: $totalFindings" -ForegroundColor $color
    Write-Host "    CRITICAL: $criticalCount" -ForegroundColor Red
    Write-Host "    WARNING:  $warningCount" -ForegroundColor DarkYellow
    Write-Host ""

    if ($criticalCount -gt 0) {
        Write-Host "  !! DO NOT RUN npm install / pip install / build commands !!" -ForegroundColor Red
        Write-Host "  !! Review the findings above and delete the repo if malicious !!" -ForegroundColor Red
    } else {
        Write-Host "  Warnings found - review before proceeding with installation." -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "  Scanned: $RepoDir" -ForegroundColor Gray
Write-Host "  Known bad packages checked: $($KnownBadPackages.Count)" -ForegroundColor Gray
Write-Host "  Config size threshold: $MaxConfigSizeChars chars" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# Exit with code 1 if critical findings (for CI integration)
if ($criticalCount -gt 0) {
    exit 1
}
exit 0
