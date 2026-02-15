Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  NPM SUPPLY CHAIN SECURITY AUDIT" -ForegroundColor Cyan
Write-Host "  $(Get-Date)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Track critical findings for summary
$findings = @()

# ============================================================
# 1. Check if stealer native modules exist on disk
# ============================================================
Write-Host "=== 1. STEALER PACKAGE BUILD ARTIFACTS (on disk) ===" -ForegroundColor Yellow
$dpapi = Test-Path "node_modules\@primno\dpapi\build"
$sqlite = Test-Path "node_modules\better-sqlite3\build"
$pkg = Test-Path "node_modules\react-svg-helper-fast"
Write-Host "  react-svg-helper-fast exists: $pkg"
Write-Host "  @primno/dpapi compiled: $dpapi"
Write-Host "  better-sqlite3 compiled: $sqlite"
if ($dpapi -and $sqlite) {
    Write-Host "  >> CRITICAL: Both native stealer modules were compiled. Theft likely occurred." -ForegroundColor Red
    $findings += "[CRITICAL] Stealer native modules compiled and present on disk"
} elseif ($pkg) {
    Write-Host "  >> WARNING: Stealer package exists but native modules may not have built." -ForegroundColor DarkYellow
    $findings += "[WARNING] Stealer package present but native modules not found on disk"
} else {
    Write-Host "  >> Package not found on disk (may have been manually deleted)." -ForegroundColor DarkYellow
    Write-Host "     NOTE: This does NOT mean it was never installed. Check npm logs below." -ForegroundColor DarkYellow
}
Write-Host ""

# ============================================================
# 2. NPM INSTALL LOGS - deep scan for stealer evidence
# ============================================================
Write-Host "=== 2. NPM INSTALL LOGS - STEALER EVIDENCE ===" -ForegroundColor Yellow
$npmLogDir = "$env:LOCALAPPDATA\npm-cache\_logs"
$stealerInstalled = $false
$stealerBuilt = $false
$stealerRunDev = $false

if (Test-Path $npmLogDir) {
    $allLogs = Get-ChildItem $npmLogDir -Filter "*.log" -ErrorAction SilentlyContinue | Sort-Object Name
    $logsWithStealer = @()

    foreach ($log in $allLogs) {
        try {
            $lines = [System.IO.File]::ReadAllLines($log.FullName)
        } catch {
            continue
        }

        $stealerLines = $lines | Where-Object { $_ -match "react-svg-helper-fast|@primno/dpapi|better-sqlite3" }
        if ($stealerLines) {
            $logsWithStealer += $log

            # Check if package was resolved/fetched
            $fetched = $stealerLines | Where-Object { $_ -match "fetch GET 200.*react-svg-helper-fast.*\.tgz" }
            if ($fetched) {
                $stealerInstalled = $true
                Write-Host "  >> FOUND: react-svg-helper-fast was DOWNLOADED" -ForegroundColor Red
                Write-Host "     Log: $($log.Name)" -ForegroundColor Gray
                $fetched | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
            }

            # Check if native modules installed successfully
            $dpapiInstall = $stealerLines | Where-Object { $_ -match "run @primno/dpapi.*install.*exit 0|run @primno/dpapi.*install.*code: 0" }
            $sqliteInstall = $stealerLines | Where-Object { $_ -match "run better-sqlite3.*install.*exit 0|run better-sqlite3.*install.*code: 0" }
            if ($dpapiInstall) {
                $stealerBuilt = $true
                Write-Host "  >> FOUND: @primno/dpapi install SUCCEEDED (exit 0)" -ForegroundColor Red
                $dpapiInstall | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
            }
            if ($sqliteInstall) {
                $stealerBuilt = $true
                Write-Host "  >> FOUND: better-sqlite3 install SUCCEEDED (exit 0)" -ForegroundColor Red
                $sqliteInstall | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
            }

            # Check if placed in node_modules
            $placed = $stealerLines | Where-Object { $_ -match "placeDep ROOT react-svg-helper-fast" }
            if ($placed) {
                Write-Host "  >> FOUND: react-svg-helper-fast placed in node_modules" -ForegroundColor Red
                $placed | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
            }

            # Show dependency resolution (what the stealer pulled in)
            $deps = $stealerLines | Where-Object { $_ -match "placeDep ROOT .* OK for: react-svg-helper-fast" }
            if ($deps) {
                Write-Host "  >> Stealer dependencies resolved:" -ForegroundColor DarkYellow
                $deps | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkYellow }
            }
        }

        # Check if npm run dev was executed (triggers PostCSS payload)
        $devRun = $lines | Where-Object { $_ -match 'verbose argv.*"run".*"dev"|verbose title npm run dev|verbose title npm run build' }
        if ($devRun) {
            $stealerRunDev = $true
        }
    }

    if ($logsWithStealer.Count -eq 0) {
        Write-Host "  No stealer references found in any npm log." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  Logs containing stealer references ($($logsWithStealer.Count)):" -ForegroundColor Gray
        $logsWithStealer | ForEach-Object { Write-Host "    $($_.Name) ($($_.LastWriteTime))" -ForegroundColor Gray }
    }

    if ($stealerInstalled) {
        $findings += "[CRITICAL] npm logs confirm react-svg-helper-fast was downloaded and installed"
    }
    if ($stealerBuilt) {
        $findings += "[CRITICAL] npm logs confirm native stealer modules (dpapi, better-sqlite3) compiled successfully"
    }
} else {
    Write-Host "  npm log directory not found." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 3. PACKAGE-LOCK.JSON - check if stealer is in lockfile
# ============================================================
Write-Host "=== 3. PACKAGE-LOCK.JSON - STEALER IN LOCKFILE ===" -ForegroundColor Yellow
if (Test-Path "package-lock.json") {
    $lockContent = Get-Content "package-lock.json" -Raw
    if ($lockContent -match 'react-svg-helper-fast') {
        Write-Host "  >> CRITICAL: react-svg-helper-fast is listed in package-lock.json" -ForegroundColor Red
        $findings += "[CRITICAL] react-svg-helper-fast present in package-lock.json"

        # Extract details from lockfile
        $lockJson = $lockContent | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($lockJson.packages.'node_modules/react-svg-helper-fast') {
            $stealerEntry = $lockJson.packages.'node_modules/react-svg-helper-fast'
            Write-Host "    Version:  $($stealerEntry.version)" -ForegroundColor Red
            Write-Host "    Resolved: $($stealerEntry.resolved)" -ForegroundColor Red
            Write-Host "    Integrity: $($stealerEntry.integrity)" -ForegroundColor Red

            if ($stealerEntry.dependencies) {
                Write-Host "    Dependencies (stealer toolkit):" -ForegroundColor Red
                $stealerEntry.dependencies.PSObject.Properties | ForEach-Object {
                    $dangerLevel = switch -Regex ($_.Name) {
                        '@primno/dpapi'    { " [DPAPI - decrypts browser passwords]" }
                        'better-sqlite3'   { " [SQLite - reads credential databases]" }
                        'node-machine-id'  { " [Machine fingerprinting]" }
                        'socket.io-client' { " [WebSocket - C2 exfiltration channel]" }
                        'request'          { " [HTTP - data exfiltration]" }
                        'express'          { " [HTTP server - possible local listener]" }
                        default            { "" }
                    }
                    Write-Host "      $($_.Name): $($_.Value)$dangerLevel" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "  react-svg-helper-fast NOT in package-lock.json." -ForegroundColor Green
    }

    if (Test-Path "package.json") {
        $pkgContent = Get-Content "package.json" -Raw
        if ($pkgContent -match 'react-svg-helper-fast') {
            Write-Host "  >> react-svg-helper-fast is also listed in package.json dependencies" -ForegroundColor Red
            $findings += "[CRITICAL] react-svg-helper-fast listed in package.json"
        }
    }
} else {
    Write-Host "  package-lock.json not found." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 4. NPM RUN DEV / BUILD - did PostCSS payload execute?
# ============================================================
Write-Host "=== 4. NPM RUN DEV/BUILD EXECUTION ===" -ForegroundColor Yellow
if ($stealerRunDev) {
    Write-Host "  >> CRITICAL: npm run dev/build was executed" -ForegroundColor Red
    Write-Host "     This triggers the PostCSS obfuscated payload (postcss.config.js)" -ForegroundColor Red
    $findings += "[CRITICAL] npm run dev/build was executed (PostCSS payload triggered)"
} else {
    Write-Host "  No evidence of npm run dev/build in logs." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 5. NPM CACHE - stealer package tarballs
# ============================================================
Write-Host "=== 5. NPM CACHE - STEALER TARBALLS ===" -ForegroundColor Yellow
$cacheHits = @()
$cacheIndexDir = "$env:LOCALAPPDATA\npm-cache\_cacache\index-v5"
if (Test-Path $cacheIndexDir) {
    $indexFiles = Get-ChildItem $cacheIndexDir -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $indexFiles) {
        try {
            $fc = [System.IO.File]::ReadAllText($f.FullName)
            if ($fc -match 'react-svg-helper-fast|rest-icon-moduler') {
                $cacheHits += $f.FullName
            }
        } catch {}
    }
}
if ($cacheHits.Count -gt 0) {
    Write-Host "  >> FOUND: Stealer package cached in npm ($($cacheHits.Count) cache entries)" -ForegroundColor Red
    Write-Host "     Run 'npm cache clean --force' to purge." -ForegroundColor Yellow
    $findings += "[WARNING] Stealer package still cached in npm cache"
} else {
    Write-Host "  No stealer tarballs found in npm cache." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 6. Browser credential DB last access times
# ============================================================
Write-Host "=== 6. BROWSER CREDENTIAL DB ACCESS TIMES ===" -ForegroundColor Yellow
$browserPaths = @(
    @{ Name="Chrome Login Data";    Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
    @{ Name="Chrome Cookies";       Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" },
    @{ Name="Chrome Local State";   Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" },
    @{ Name="Edge Login Data";      Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
    @{ Name="Edge Cookies";         Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" },
    @{ Name="Edge Local State";     Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" },
    @{ Name="Opera Login Data";     Path="$env:APPDATA\Opera Software\Opera Stable\Login Data" },
    @{ Name="Opera Cookies";        Path="$env:APPDATA\Opera Software\Opera Stable\Cookies" }
)
foreach ($b in $browserPaths) {
    if (Test-Path $b.Path) {
        $item = Get-Item $b.Path
        Write-Host "  $($b.Name):"
        Write-Host "    Last Access: $($item.LastAccessTime)"
        Write-Host "    Last Write:  $($item.LastWriteTime)"
    }
}
Write-Host ""

# ============================================================
# 7. DNS cache - check for attacker domains
# ============================================================
Write-Host "=== 7. DNS CACHE - ATTACKER DOMAINS ===" -ForegroundColor Yellow
$suspiciousDns = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { 
    $_.Entry -match 'vercel|rest-icon|moduler|vscode-extension-260120' 
}
if ($suspiciousDns) {
    Write-Host "  >> FOUND attacker domains in DNS cache:" -ForegroundColor Red
    $suspiciousDns | Format-Table Entry, Data -AutoSize | Out-String | Write-Host
    $findings += "[CRITICAL] Attacker domains found in DNS cache"
} else {
    Write-Host "  No attacker domains found in DNS cache." -ForegroundColor Green
    Write-Host "  NOTE: DNS cache is short-lived. Absence does not mean domains were never contacted." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 8. Credential DB copies in temp directories
# ============================================================
Write-Host "=== 8. CREDENTIAL DB COPIES IN TEMP ===" -ForegroundColor Yellow
$suspiciousFiles = Get-ChildItem $env:TEMP, "$env:LOCALAPPDATA\Temp" -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match 'Login Data|Cookies|Local State|Web Data|\.sqlite|credential' -and $_.CreationTime -gt (Get-Date).AddDays(-7) } |
    Where-Object { $_.FullName -notmatch 'dotnet-suggest-registration' }
if ($suspiciousFiles) {
    Write-Host "  >> SUSPICIOUS credential-like files found:" -ForegroundColor Red
    $suspiciousFiles | Select-Object FullName, CreationTime, Length | Format-Table -AutoSize | Out-String | Write-Host
    $findings += "[WARNING] Suspicious credential-like files in temp directories"
} else {
    Write-Host "  No suspicious copies found." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 9. Node_modules malicious package details (if still present)
# ============================================================
Write-Host "=== 9. MALICIOUS PACKAGE ON DISK ===" -ForegroundColor Yellow
$malPkg = "node_modules\react-svg-helper-fast\package.json"
if (Test-Path $malPkg) {
    Write-Host "  >> Malicious package found on disk:" -ForegroundColor Red
    $pkgJson = Get-Content $malPkg -Raw | ConvertFrom-Json
    Write-Host "    Name: $($pkgJson.name)"
    Write-Host "    Version: $($pkgJson.version)"
    Write-Host "    Description: $($pkgJson.description)"
    if ($pkgJson.scripts) {
        Write-Host "    Scripts:" -ForegroundColor Red
        $pkgJson.scripts | Format-List | Out-String | Write-Host
    }
    if ($pkgJson.dependencies) {
        Write-Host "    Dependencies:" -ForegroundColor Red
        $pkgJson.dependencies | Format-List | Out-String | Write-Host
    }
    $findings += "[CRITICAL] Malicious package still present on disk"
} else {
    Write-Host "  Malicious package not in node_modules (deleted or never extracted)." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 10. PostCSS config payload
# ============================================================
Write-Host "=== 10. POSTCSS.CONFIG.JS PAYLOAD ===" -ForegroundColor Yellow
if (Test-Path "postcss.config.js") {
    $content = Get-Content "postcss.config.js" -Raw
    $len = $content.Length
    Write-Host "  File size: $len characters"
    if ($len -gt 500) {
        Write-Host "  >> CRITICAL: postcss.config.js is $len chars (normal is ~200). Contains hidden payload." -ForegroundColor Red
        if ($content -match 'fromCharCode|_\$_|createRequire|global\.require|\\x[0-9a-f]{2}') {
            Write-Host "  >> Obfuscation patterns detected: fromCharCode, hex encoding, global.require injection" -ForegroundColor Red
        }
        $findings += "[CRITICAL] postcss.config.js contains obfuscated payload"
    } else {
        Write-Host "  File size appears normal." -ForegroundColor Green
    }
} else {
    Write-Host "  postcss.config.js not found (deleted or never present)." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 11. .vscode/tasks.json curl-pipe-shell
# ============================================================
Write-Host "=== 11. VSCODE TASKS.JSON ===" -ForegroundColor Yellow
if (Test-Path ".vscode\tasks.json") {
    $tasks = Get-Content ".vscode\tasks.json" -Raw
    if ($tasks -match 'curl.*\|.*cmd|curl.*\|.*bash|curl.*\|.*sh') {
        Write-Host "  >> CRITICAL: tasks.json contains curl-pipe-to-shell attack" -ForegroundColor Red
        $findings += "[CRITICAL] .vscode/tasks.json curl-pipe-shell still present"
    } else {
        Write-Host "  tasks.json exists but no curl-pipe-shell found." -ForegroundColor Green
    }
} else {
    Write-Host "  tasks.json not found (already deleted)." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 12. Exposed secrets in .env
# ============================================================
Write-Host "=== 12. EXPOSED SECRETS ===" -ForegroundColor Yellow
if (Test-Path ".env") {
    $envContent = Get-Content ".env" -Raw
    if ($envContent -match 'SECRET_KEY|PRIVATE_KEY|secret|password') {
        Write-Host "  >> WARNING: .env file contains secret keys that are likely compromised" -ForegroundColor Red
        Get-Content ".env" | ForEach-Object {
            if ($_ -match '^([^=]+)=') {
                Write-Host "    Key found: $($Matches[1])"
            }
        }
        $findings += "[WARNING] .env contains exposed secret keys"
    }
} else {
    Write-Host "  No .env file found." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 13. Active node network connections
# ============================================================
Write-Host "=== 13. ACTIVE NODE NETWORK CONNECTIONS ===" -ForegroundColor Yellow
$nodeConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
    try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -match 'node' } catch { $false }
}
if ($nodeConns) {
    Write-Host "  Active node.exe connections:"
    $nodeConns | Select-Object RemoteAddress, RemotePort, State | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "  No active node network connections." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 14. Registry Run keys (persistence check)
# ============================================================
Write-Host "=== 14. REGISTRY AUTOSTART ENTRIES ===" -ForegroundColor Yellow
$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        if ($props) {
            Write-Host "  $key :" -ForegroundColor Gray
            foreach ($p in $props) {
                $suspicious = $false
                if ($p.Value -match 'curl|node_modules|react-svg|appdata.*\\temp|powershell.*-enc|cmd.*/c') {
                    $suspicious = $true
                    $findings += "[CRITICAL] Suspicious autostart entry: $($p.Name)"
                }
                $color = if ($suspicious) { "Red" } else { "White" }
                Write-Host "    $($p.Name): $($p.Value)" -ForegroundColor $color
            }
        }
    }
}
Write-Host ""

# ============================================================
# 15. Startup folder
# ============================================================
Write-Host "=== 15. STARTUP FOLDER ===" -ForegroundColor Yellow
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupPath) {
    $startupItems = Get-ChildItem $startupPath -ErrorAction SilentlyContinue
    if ($startupItems) {
        foreach ($item in $startupItems) {
            $suspicious = $item.CreationTime -gt (Get-Date).AddDays(-7)
            $color = if ($suspicious) { "DarkYellow" } else { "White" }
            Write-Host "  $($item.Name) (Created: $($item.CreationTime))" -ForegroundColor $color
        }
    } else {
        Write-Host "  Startup folder is empty." -ForegroundColor Green
    }
} else {
    Write-Host "  Startup folder not found." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 16. Scheduled tasks (non-Microsoft)
# ============================================================
Write-Host "=== 16. NON-MICROSOFT SCHEDULED TASKS ===" -ForegroundColor Yellow
$customTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
    $_.State -ne 'Disabled' -and $_.Author -notmatch 'Microsoft' -and $_.Author 
}
if ($customTasks) {
    $customTasks | Select-Object TaskName, Author, State, @{N='Action';E={($_.Actions | Select-Object -First 1).Execute}} | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "  No non-Microsoft scheduled tasks found." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 17. Windows Defender detection history
# ============================================================
Write-Host "=== 17. WINDOWS DEFENDER DETECTIONS ===" -ForegroundColor Yellow
try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-7) }
    if ($threats) {
        Write-Host "  >> FOUND: Defender detected threats in the last 7 days:" -ForegroundColor Red
        $threats | Select-Object ThreatID, @{N='Threat';E={$_.ThreatName}}, InitialDetectionTime, @{N='Path';E={$_.Resources}} | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Windows Defender detected threats recently"
    } else {
        Write-Host "  No Defender detections in last 7 days." -ForegroundColor Green
    }

    $quarantined = Get-MpThreat -ErrorAction SilentlyContinue
    if ($quarantined) {
        Write-Host "  Quarantined threats:" -ForegroundColor DarkYellow
        $quarantined | Select-Object ThreatID, ThreatName, IsActive | Format-Table -AutoSize | Out-String | Write-Host
    }
} catch {
    Write-Host "  Could not query Defender (may require admin)." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 18. Windows Prefetch (proof of execution)
# ============================================================
Write-Host "=== 18. WINDOWS PREFETCH - EXECUTION EVIDENCE ===" -ForegroundColor Yellow
$prefetchDir = "C:\Windows\Prefetch"
if (Test-Path $prefetchDir) {
    $suspiciousPrefetch = Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'NODE|CURL|CMD' -and $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
    if ($suspiciousPrefetch) {
        Write-Host "  Executables ran in last 24 hours (matching NODE/CURL/CMD):" -ForegroundColor DarkYellow
        $suspiciousPrefetch | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "  No recent NODE/CURL/CMD prefetch entries." -ForegroundColor Green
    }
} else {
    Write-Host "  Prefetch directory not accessible." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 19. PowerShell script block logging
# ============================================================
Write-Host "=== 19. POWERSHELL SCRIPT BLOCK LOGS ===" -ForegroundColor Yellow
try {
    $psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'curl|dpapi|sqlite|react-svg|credential|password|cookie|fromCharCode' }
    if ($psLogs) {
        Write-Host "  >> FOUND suspicious PowerShell script block logs:" -ForegroundColor Red
        $psLogs | Select-Object TimeCreated, @{N='Snippet';E={$_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))}} -First 5 | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Suspicious PowerShell script block logs found"
    } else {
        Write-Host "  No suspicious script blocks logged." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not read PowerShell operational log." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 20. BITS transfer jobs (data exfiltration check)
# ============================================================
Write-Host "=== 20. BITS TRANSFER JOBS ===" -ForegroundColor Yellow
try {
    $bits = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    if ($bits) {
        Write-Host "  >> FOUND active BITS transfers:" -ForegroundColor Red
        $bits | Select-Object DisplayName, TransferType, JobState, @{N='Files';E={$_.FileList}} | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Active BITS transfer jobs found"
    } else {
        Write-Host "  No active BITS transfers." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query BITS (may require admin)." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 21. Outbound firewall rules (persistence check)
# ============================================================
Write-Host "=== 21. CUSTOM OUTBOUND FIREWALL RULES ===" -ForegroundColor Yellow
try {
    $fwRules = Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notmatch 'Microsoft|Windows|Core Networking' -and $_.Enabled -eq 'True' }
    if ($fwRules) {
        $fwRules | Select-Object DisplayName, Description, @{N='Program';E={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue).Program}} |
            Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "  No custom outbound firewall rules." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query firewall rules." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 22. Sysmon logs (if installed)
# ============================================================
Write-Host "=== 22. SYSMON LOGS ===" -ForegroundColor Yellow
try {
    # Process creation
    $sysmonProc = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 300 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'node|curl|react-svg|dpapi|sqlite' }
    if ($sysmonProc) {
        Write-Host "  >> FOUND Sysmon process creation events:" -ForegroundColor Red
        $sysmonProc | Select-Object TimeCreated, @{N='Detail';E={($_.Message -split "`n")[0..3] -join " "}} -First 10 | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Sysmon logged suspicious process creation"
    } else {
        Write-Host "  No suspicious process creation events." -ForegroundColor Green
    }

    # Network connections
    $sysmonNet = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 300 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'node\.exe' }
    if ($sysmonNet) {
        Write-Host "  >> FOUND Sysmon network events for node.exe:" -ForegroundColor Red
        $sysmonNet | Select-Object TimeCreated, @{N='Detail';E={($_.Message -split "`n")[0..5] -join " "}} -First 10 | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Sysmon logged node.exe network connections"
    } else {
        Write-Host "  No node.exe network events in Sysmon." -ForegroundColor Green
    }
} catch {
    Write-Host "  Sysmon not installed or not accessible." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 23. Network activity (Windows Filtering Platform)
# ============================================================
Write-Host "=== 23. WINDOWS FILTERING PLATFORM - NETWORK LOGS ===" -ForegroundColor Yellow
try {
    $wfpEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156} -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'node\.exe|curl\.exe' }
    if ($wfpEvents) {
        Write-Host "  >> FOUND network events for node/curl:" -ForegroundColor Red
        $wfpEvents | Select-Object TimeCreated, @{N='Detail';E={($_.Message -split "`n")[0..5] -join " "}} -First 10 | Format-List | Out-String | Write-Host
        $findings += "[WARNING] WFP logged node/curl network activity"
    } else {
        Write-Host "  No node/curl network events in WFP logs." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not read WFP logs (requires admin or audit logging)." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# 24. Crypto wallet directories
# ============================================================
Write-Host "=== 24. CRYPTO WALLET DIRECTORIES ===" -ForegroundColor Yellow
$walletPaths = @(
    @{ Name="Exodus";      Path="$env:APPDATA\Exodus" },
    @{ Name="Atomic";      Path="$env:APPDATA\atomic" },
    @{ Name="Electrum";    Path="$env:APPDATA\Electrum" },
    @{ Name="Ethereum";    Path="$env:APPDATA\Ethereum" },
    @{ Name="Coinomi";     Path="$env:LOCALAPPDATA\Coinomi" },
    @{ Name="MetaMask";    Path="$env:APPDATA\MetaMask" },
    @{ Name="Phantom";     Path="$env:APPDATA\Phantom" },
    @{ Name="Solflare";    Path="$env:APPDATA\Solflare" },
    @{ Name="Brave Wallet"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings" }
)
$walletsFound = $false
foreach ($w in $walletPaths) {
    if (Test-Path $w.Path) {
        $walletsFound = $true
        $item = Get-Item $w.Path
        Write-Host "  >> FOUND: $($w.Name) at $($w.Path)" -ForegroundColor Red
        Write-Host "     Last Access: $($item.LastAccessTime)" -ForegroundColor DarkYellow
        $findings += "[WARNING] Crypto wallet found: $($w.Name) - may have been accessed by stealer"
    }
}
if (-not $walletsFound) {
    Write-Host "  No known crypto wallet directories found." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 25. SSH keys and Git credentials
# ============================================================
Write-Host "=== 25. SSH KEYS & GIT CREDENTIALS ===" -ForegroundColor Yellow
# SSH keys
$sshDir = "$env:USERPROFILE\.ssh"
if (Test-Path $sshDir) {
    Write-Host "  SSH directory found:" -ForegroundColor DarkYellow
    Get-ChildItem $sshDir -ErrorAction SilentlyContinue | Select-Object Name, LastAccessTime, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
    $findings += "[WARNING] SSH keys present - rotate if compromise suspected"
} else {
    Write-Host "  No .ssh directory." -ForegroundColor Green
}

# Git credentials (plaintext)
$gitCreds = "$env:USERPROFILE\.git-credentials"
if (Test-Path $gitCreds) {
    Write-Host "  >> WARNING: .git-credentials file exists (plaintext tokens!)" -ForegroundColor Red
    Get-Item $gitCreds | Select-Object LastAccessTime, LastWriteTime, Length | Format-List | Out-String | Write-Host
    $findings += "[CRITICAL] .git-credentials file with plaintext tokens exists"
} else {
    Write-Host "  No .git-credentials file (good)." -ForegroundColor Green
}

# GitHub CLI tokens
$ghCli = "$env:APPDATA\GitHub CLI"
if (Test-Path $ghCli) {
    Write-Host "  GitHub CLI config found:" -ForegroundColor DarkYellow
    Get-ChildItem $ghCli -ErrorAction SilentlyContinue | Select-Object Name, LastAccessTime | Format-Table -AutoSize | Out-String | Write-Host
    $findings += "[WARNING] GitHub CLI tokens present - revoke if compromise suspected"
} else {
    Write-Host "  No GitHub CLI config." -ForegroundColor Green
}

# npm tokens
$npmrc = "$env:USERPROFILE\.npmrc"
if (Test-Path $npmrc) {
    $npmContent = Get-Content $npmrc -Raw -ErrorAction SilentlyContinue
    if ($npmContent -match 'authToken|_auth') {
        Write-Host "  >> WARNING: .npmrc contains auth tokens" -ForegroundColor Red
        $findings += "[WARNING] .npmrc contains npm auth tokens"
    }
}
Write-Host ""

# ============================================================
# 26. Windows Error Reporting / Crash dumps
# ============================================================
Write-Host "=== 26. CRASH DUMPS & ERROR REPORTS ===" -ForegroundColor Yellow
$crashDumps = Get-ChildItem "$env:LOCALAPPDATA\CrashDumps" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'node' -and $_.CreationTime -gt (Get-Date).AddDays(-1) }
if ($crashDumps) {
    Write-Host "  >> Node.js crash dumps found:" -ForegroundColor Red
    $crashDumps | Select-Object Name, CreationTime | Format-Table -AutoSize | Out-String | Write-Host
    $findings += "[INFO] Node.js crash dumps found (stealer may have crashed)"
} else {
    Write-Host "  No recent node.js crash dumps." -ForegroundColor Green
}

$werFiles = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\WER" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) }
if ($werFiles) {
    Write-Host "  Recent WER reports:" -ForegroundColor DarkYellow
    $werFiles | Select-Object FullName, CreationTime | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "  No recent WER reports." -ForegroundColor Green
}
Write-Host ""

# ============================================================
# 27. Windows Event Log - suspicious process creation
# ============================================================
Write-Host "=== 27. SECURITY EVENT LOG - PROCESS CREATION ===" -ForegroundColor Yellow
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'curl|powershell.*-enc|cmd.*/c.*curl|node.*react-svg' }
    if ($events) {
        Write-Host "  >> Suspicious process creation events found:" -ForegroundColor Red
        $events | Select-Object TimeCreated, @{N='Detail';E={($_.Message -split "`n")[0..3] -join " "}} -First 10 | Format-List | Out-String | Write-Host
        $findings += "[WARNING] Suspicious process creation events in Security event log"
    } else {
        Write-Host "  No suspicious process events found (or audit logging not enabled)." -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not read Security event log (requires admin)." -ForegroundColor Gray
}
Write-Host ""

# ============================================================
# SUMMARY
# ============================================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "  No findings detected." -ForegroundColor Green
} else {
    $critCount = ($findings | Where-Object { $_ -match '^\[CRITICAL\]' }).Count
    $warnCount = ($findings | Where-Object { $_ -match '^\[WARNING\]' }).Count
    $infoCount = ($findings | Where-Object { $_ -match '^\[INFO\]' }).Count
    Write-Host "  Total findings: $($findings.Count) ($critCount critical, $warnCount warnings, $infoCount info)" -ForegroundColor Red
    Write-Host ""
    foreach ($f in $findings) {
        $color = switch -Regex ($f) {
            '^\[CRITICAL\]' { "Red" }
            '^\[WARNING\]'  { "DarkYellow" }
            default         { "Gray" }
        }
        Write-Host "  $f" -ForegroundColor $color
    }
}

Write-Host ""
Write-Host "  --------------------------------------------------" -ForegroundColor Gray
Write-Host "  ASSESSMENT:" -ForegroundColor Cyan
if ($stealerInstalled -and $stealerBuilt) {
    Write-Host "  The stealer package was DOWNLOADED, its native modules" -ForegroundColor Red
    Write-Host "  COMPILED SUCCESSFULLY, and npm run dev/build was executed." -ForegroundColor Red
    Write-Host "  Browser credential theft LIKELY OCCURRED." -ForegroundColor Red
    Write-Host ""
    Write-Host "  IMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Red
    Write-Host "    1. Change ALL passwords saved in Chrome/Edge/Opera" -ForegroundColor Yellow
    Write-Host "    2. Revoke all active browser sessions (Google, GitHub, etc.)" -ForegroundColor Yellow
    Write-Host "    3. Enable 2FA on all accounts" -ForegroundColor Yellow
    Write-Host "    4. Rotate all API keys/tokens on this machine" -ForegroundColor Yellow
    Write-Host "    5. Rotate SSH keys and Git credentials" -ForegroundColor Yellow
    Write-Host "    6. Move crypto wallet funds to new wallets" -ForegroundColor Yellow
    Write-Host "    7. Delete this repo: Remove-Item -Recurse -Force ." -ForegroundColor Yellow
    Write-Host "    8. Clean npm cache: npm cache clean --force" -ForegroundColor Yellow
} elseif ($stealerInstalled) {
    Write-Host "  The stealer package was downloaded but native modules" -ForegroundColor DarkYellow
    Write-Host "  may not have compiled. Partial compromise possible." -ForegroundColor DarkYellow
    Write-Host "  Recommend changing browser-saved passwords as a precaution." -ForegroundColor Yellow
} else {
    Write-Host "  No evidence the stealer package was installed." -ForegroundColor Green
    Write-Host "  However, if node_modules were manually deleted before" -ForegroundColor DarkYellow
    Write-Host "  this scan, evidence may have been removed." -ForegroundColor DarkYellow
    Write-Host "  Change browser-saved passwords as a precaution." -ForegroundColor Yellow
}
Write-Host "  --------------------------------------------------" -ForegroundColor Gray
Write-Host ""
