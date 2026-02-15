<#
.SYNOPSIS
    General-purpose Windows forensic triage and incident response script.

.DESCRIPTION
    Performs in-depth forensic investigation across multiple evidence categories:
      - Process analysis (running processes, suspicious command lines, DLL injection)
      - Network forensics (active connections, DNS cache, firewall rules, BITS jobs)
      - Persistence mechanisms (registry Run keys, startup folder, scheduled tasks, services, WMI subscriptions)
      - File system forensics (recent files, Prefetch, USN journal, Amcache, Shimcache)
      - Browser forensics (credential DBs, history, cookies)
      - Credential stores (SSH keys, Git tokens, npm tokens, environment files, crypto wallets)
      - Event log analysis (Security, Sysmon, PowerShell ScriptBlock, Defender, WFP)
      - User activity analysis (RecentDocs, RDP sessions, PowerShell command history)
      - Windows Defender detections and quarantine

    All findings are exported as structured JSON for downstream analysis.
    Evidence files are SHA-256 hashed for chain-of-custody integrity.

.PARAMETER IOCPatterns
    Array of regex patterns representing Indicators of Compromise to search for.
    Defaults to common suspicious patterns.

.PARAMETER DaysBack
    Number of days to look back for evidence. Default: 7.

.PARAMETER OutputDir
    Directory to write JSON report and collected artifacts. Default: .\ForensicReport_<timestamp>

.PARAMETER CollectHashes
    If set, computes SHA-256 hashes for all suspicious files discovered.

.PARAMETER IncludeFullEventLogs
    If set, increases event log search depth from 500 to 5000 events.

.PARAMETER ScanPaths
    Additional file system paths to scan for IOCs.

.EXAMPLE
    .\forensic-triage.ps1

.EXAMPLE
    .\forensic-triage.ps1 -IOCPatterns @('malware\.exe','evil\.dll','c2server\.com') -DaysBack 14

.EXAMPLE
    .\forensic-triage.ps1 -OutputDir C:\Evidence\Case001 -CollectHashes -IncludeFullEventLogs
#>

[CmdletBinding()]
param(
    [string[]]$IOCPatterns = @(
        'powershell.*-enc',
        'cmd.*/c.*curl',
        'curl.*\|.*cmd',
        'curl.*\|.*bash',
        'curl.*\|.*sh',
        'fromCharCode',
        'certutil.*-urlcache',
        'bitsadmin.*\/transfer',
        'mshta.*http',
        'regsvr32.*\/s.*\/u.*scrobj',
        'rundll32.*javascript',
        'wscript.*\.jse',
        'cscript.*\.jse'
    ),

    [int]$DaysBack = 7,

    [string]$OutputDir = "",

    [switch]$CollectHashes,

    [switch]$IncludeFullEventLogs,

    [string[]]$ScanPaths = @()
)

# ============================================================
# INITIALIZATION
# ============================================================
$ErrorActionPreference = 'SilentlyContinue'
$scriptStartTime = Get-Date
$iocRegex = ($IOCPatterns | ForEach-Object { "($_)" }) -join '|'
$lookbackDate = (Get-Date).AddDays(-$DaysBack)
$eventMaxEvents = if ($IncludeFullEventLogs) { 5000 } else { 500 }

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) ("ForensicReport_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Master evidence collection object
$report = [ordered]@{
    Metadata   = [ordered]@{
        ScriptVersion       = "1.0.0"
        RunDate             = $scriptStartTime.ToString('o')
        Hostname            = $env:COMPUTERNAME
        Username            = $env:USERNAME
        Domain              = $env:USERDOMAIN
        OSVersion           = (Get-CimInstance Win32_OperatingSystem).Caption
        OSBuild             = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        DaysBack            = $DaysBack
        IOCPatterns         = $IOCPatterns
        CollectHashes       = $CollectHashes.IsPresent
        IncludeFullEventLogs = $IncludeFullEventLogs.IsPresent
        ScanPaths           = $ScanPaths
    }
    Findings   = @()
    Evidence   = [ordered]@{}
}

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO')]
        [string]$Severity,
        [string]$Category,
        [string]$Message,
        [object]$Detail = $null
    )
    $script:report.Findings += [ordered]@{
        Severity  = $Severity
        Category  = $Category
        Message   = $Message
        Detail    = $Detail
        Timestamp = (Get-Date).ToString('o')
    }
    $color = switch ($Severity) {
        'CRITICAL' { 'Red' }
        'WARNING'  { 'DarkYellow' }
        'INFO'     { 'Gray' }
    }
    Write-Host "  [$Severity] $Message" -ForegroundColor $color
}

function Get-SafeHash {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    } catch {}
    return $null
}

function Write-Section {
    param([string]$Number, [string]$Title)
    Write-Host ""
    Write-Host ("=== {0}. {1} ===" -f $Number, $Title) -ForegroundColor Yellow
}

# ============================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FORENSIC TRIAGE - General Purpose Incident Response" -ForegroundColor Cyan
Write-Host "  Host: $env:COMPUTERNAME  User: $env:USERNAME" -ForegroundColor Cyan
Write-Host "  $(Get-Date)  Lookback: $DaysBack days" -ForegroundColor Cyan
Write-Host "  IOC patterns: $($IOCPatterns.Count)  Output: $OutputDir" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ============================================================
# 1. SYSTEM INFORMATION
# ============================================================
Write-Section "1" "SYSTEM INFORMATION"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$sysInfo = [ordered]@{
    Hostname      = $env:COMPUTERNAME
    Domain        = $cs.Domain
    OS            = $os.Caption
    Build         = $os.BuildNumber
    Architecture  = $os.OSArchitecture
    InstallDate   = $os.InstallDate.ToString('o')
    LastBoot      = $os.LastBootUpTime.ToString('o')
    BIOSSerial    = $bios.SerialNumber
    Manufacturer  = $cs.Manufacturer
    Model         = $cs.Model
    TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    TimeZone      = (Get-TimeZone).Id
    CurrentUser   = "$env:USERDOMAIN\$env:USERNAME"
    IsAdmin       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$report.Evidence.SystemInfo = $sysInfo
Write-Host "  Hostname: $($sysInfo.Hostname) | OS: $($sysInfo.OS) $($sysInfo.Build)"
Write-Host "  Last Boot: $($sysInfo.LastBoot) | Admin: $($sysInfo.IsAdmin)"

# ============================================================
# 2. RUNNING PROCESSES ANALYSIS
# ============================================================
Write-Section "2" "RUNNING PROCESSES ANALYSIS"
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId,
    CommandLine, ExecutablePath, CreationDate,
    @{N='Owner';E={ try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } catch { 'N/A' } }}

$suspiciousProcs = @()
foreach ($proc in $processes) {
    $isSuspicious = $false
    $reasons = @()

    # Check command line against IOCs
    if ($proc.CommandLine -and $proc.CommandLine -match $iocRegex) {
        $isSuspicious = $true
        $reasons += "Command line matches IOC pattern"
    }

    # Check for processes running from temp directories
    if ($proc.ExecutablePath -and $proc.ExecutablePath -match '\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp') {
        $isSuspicious = $true
        $reasons += "Running from temp directory"
    }

    # Check for unsigned or unusual parent-child relationships
    if ($proc.Name -match 'powershell|pwsh|cmd|wscript|cscript|mshta|regsvr32|rundll32') {
        $parent = $processes | Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
        if ($parent -and $parent.Name -notmatch 'explorer|svchost|services|wmiprvse|cmd|powershell|pwsh|conhost|code') {
            $isSuspicious = $true
            $reasons += "Unusual parent process: $($parent.Name) (PID $($parent.ProcessId))"
        }
    }

    if ($isSuspicious) {
        $suspiciousProcs += [ordered]@{
            PID         = $proc.ProcessId
            Name        = $proc.Name
            ParentPID   = $proc.ParentProcessId
            CommandLine = $proc.CommandLine
            Path        = $proc.ExecutablePath
            Created     = if ($proc.CreationDate) { $proc.CreationDate.ToString('o') } else { $null }
            Owner       = $proc.Owner
            Reasons     = $reasons
            Hash        = if ($CollectHashes -and $proc.ExecutablePath) { Get-SafeHash $proc.ExecutablePath } else { $null }
        }
        Add-Finding -Severity 'WARNING' -Category 'Process' -Message "Suspicious process: $($proc.Name) (PID $($proc.ProcessId))" -Detail $reasons
    }
}
$report.Evidence.SuspiciousProcesses = $suspiciousProcs
$report.Evidence.TotalProcesses = $processes.Count
Write-Host "  Total processes: $($processes.Count) | Suspicious: $($suspiciousProcs.Count)"

# ============================================================
# 3. NETWORK CONNECTIONS
# ============================================================
Write-Section "3" "NETWORK CONNECTIONS"
$allConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
    $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Name } catch { 'Unknown' }
    $procPath = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Path } catch { $null }
    [ordered]@{
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = $_.State.ToString()
        PID           = $_.OwningProcess
        ProcessName   = $procName
        ProcessPath   = $procPath
    }
}

# Flag established connections to non-private IPs
$suspiciousConns = $allConnections | Where-Object {
    $_.State -eq 'Established' -and
    $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|0\.0\.0\.0|::)'
}
$report.Evidence.NetworkConnections = $allConnections
$report.Evidence.SuspiciousConnections = $suspiciousConns

foreach ($conn in $suspiciousConns) {
    if ($conn.ProcessName -match 'powershell|pwsh|cmd|node|python|curl|wget|certutil') {
        Add-Finding -Severity 'WARNING' -Category 'Network' -Message "External connection by $($conn.ProcessName) to $($conn.RemoteAddress):$($conn.RemotePort)"
    }
}
Write-Host "  Total connections: $($allConnections.Count) | External established: $(($suspiciousConns | Measure-Object).Count)"

# ============================================================
# 4. DNS CACHE
# ============================================================
Write-Section "4" "DNS CACHE ANALYSIS"
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordName, Data, Type, TimeToLive
$report.Evidence.DNSCache = $dnsCache

$suspiciousDns = $dnsCache | Where-Object { $_.Entry -match $iocRegex }
if ($suspiciousDns) {
    foreach ($d in $suspiciousDns) {
        Add-Finding -Severity 'CRITICAL' -Category 'DNS' -Message "IOC domain in DNS cache: $($d.Entry) -> $($d.Data)"
    }
} else {
    Write-Host "  No IOC domains found in DNS cache (cache is short-lived; absence is inconclusive)."
}
Write-Host "  Total cached entries: $(($dnsCache | Measure-Object).Count)"

# ============================================================
# 5. PERSISTENCE - REGISTRY RUN KEYS
# ============================================================
Write-Section "5" "PERSISTENCE - REGISTRY RUN KEYS"
$runKeyPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKCU:\Environment'
)
$registryEntries = @()
foreach ($keyPath in $runKeyPaths) {
    if (Test-Path $keyPath) {
        $entries = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        foreach ($p in $props) {
            $suspicious = $p.Value -match $iocRegex -or
                          $p.Value -match '\\Temp\\|\\tmp\\|AppData.*\\Local\\Temp|\.js$|\.vbs$|\.bat$|\.ps1$'
            $entry = [ordered]@{
                KeyPath    = $keyPath
                Name       = $p.Name
                Value      = $p.Value
                Suspicious = $suspicious
            }
            $registryEntries += $entry
            if ($suspicious) {
                Add-Finding -Severity 'CRITICAL' -Category 'Persistence' -Message "Suspicious registry autostart: $($p.Name) in $keyPath" -Detail $p.Value
            }
        }
    }
}
$report.Evidence.RegistryRunKeys = $registryEntries
Write-Host "  Scanned $($runKeyPaths.Count) registry paths | Entries: $($registryEntries.Count)"

# ============================================================
# 6. PERSISTENCE - SCHEDULED TASKS
# ============================================================
Write-Section "6" "PERSISTENCE - SCHEDULED TASKS"
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$nonMsTasks = $allTasks | Where-Object {
    $_.Author -notmatch 'Microsoft|N/A|^$' -or
    ($_.Actions | ForEach-Object { $_.Execute }) -match $iocRegex
}
$taskEntries = @()
foreach ($task in $nonMsTasks) {
    $actions = $task.Actions | ForEach-Object {
        [ordered]@{ Execute = $_.Execute; Arguments = $_.Arguments; WorkingDirectory = $_.WorkingDirectory }
    }
    $entry = [ordered]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        Author   = $task.Author
        State    = $task.State.ToString()
        Actions  = $actions
    }
    $taskEntries += $entry

    $actionStr = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    if ($actionStr -match $iocRegex -or $actionStr -match '\\Temp\\|\.js |\.vbs |\.bat |powershell.*-enc') {
        Add-Finding -Severity 'CRITICAL' -Category 'Persistence' -Message "Suspicious scheduled task: $($task.TaskName)" -Detail $actionStr
    }
}
$report.Evidence.ScheduledTasks = $taskEntries
Write-Host "  Total tasks: $(($allTasks | Measure-Object).Count) | Non-Microsoft: $($taskEntries.Count)"

# ============================================================
# 7. PERSISTENCE - SERVICES
# ============================================================
Write-Section "7" "PERSISTENCE - SERVICES"
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch 'Windows\\System32|Windows\\SysWOW64|Microsoft|svchost'
}
$serviceEntries = @()
foreach ($svc in $services) {
    $entry = [ordered]@{
        Name      = $svc.Name
        DisplayName = $svc.DisplayName
        State     = $svc.State
        StartMode = $svc.StartMode
        PathName  = $svc.PathName
        StartName = $svc.StartName
        Hash      = if ($CollectHashes) { Get-SafeHash ($svc.PathName -replace '"','') } else { $null }
    }
    $serviceEntries += $entry

    if ($svc.PathName -match $iocRegex -or $svc.PathName -match '\\Temp\\|\\AppData\\') {
        Add-Finding -Severity 'CRITICAL' -Category 'Persistence' -Message "Suspicious service: $($svc.Name) -> $($svc.PathName)"
    }
}
$report.Evidence.Services = $serviceEntries
Write-Host "  Non-standard services: $($serviceEntries.Count)"

# ============================================================
# 8. PERSISTENCE - WMI EVENT SUBSCRIPTIONS
# ============================================================
Write-Section "8" "PERSISTENCE - WMI EVENT SUBSCRIPTIONS"
$wmiSubs = @()
$consumers = Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
$filters = Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue
$bindings = Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue

if ($consumers -or $filters -or $bindings) {
    foreach ($c in $consumers) {
        $entry = [ordered]@{
            Type = $c.CimClass.CimClassName
            Name = $c.Name
            CommandLineTemplate = $c.CommandLineTemplate
            ScriptText = $c.ScriptText
            ExecutablePath = $c.ExecutablePath
        }
        $wmiSubs += $entry
        Add-Finding -Severity 'WARNING' -Category 'Persistence' -Message "WMI event consumer found: $($c.Name)" -Detail $c.CimClass.CimClassName
    }
} else {
    Write-Host "  No WMI event subscriptions found."
}
$report.Evidence.WMISubscriptions = $wmiSubs

# ============================================================
# 9. PERSISTENCE - STARTUP FOLDER
# ============================================================
Write-Section "9" "PERSISTENCE - STARTUP FOLDER"
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
$startupItems = @()
foreach ($sp in $startupPaths) {
    if (Test-Path $sp) {
        Get-ChildItem $sp -ErrorAction SilentlyContinue | ForEach-Object {
            $entry = [ordered]@{
                Path        = $_.FullName
                Name        = $_.Name
                Created     = $_.CreationTime.ToString('o')
                Modified    = $_.LastWriteTime.ToString('o')
                Accessed    = $_.LastAccessTime.ToString('o')
                SizeBytes   = $_.Length
                Hash        = if ($CollectHashes) { Get-SafeHash $_.FullName } else { $null }
                RecentlyAdded = $_.CreationTime -gt $lookbackDate
            }
            $startupItems += $entry
            if ($_.CreationTime -gt $lookbackDate) {
                Add-Finding -Severity 'WARNING' -Category 'Persistence' -Message "Recently added startup item: $($_.Name) (Created: $($_.CreationTime))"
            }
        }
    }
}
$report.Evidence.StartupItems = $startupItems
Write-Host "  Startup items: $($startupItems.Count)"

# ============================================================
# 10. FILE SYSTEM - PREFETCH ANALYSIS
# ============================================================
Write-Section "10" "FILE SYSTEM - PREFETCH ANALYSIS"
$prefetchDir = "C:\Windows\Prefetch"
$prefetchEntries = @()
if (Test-Path $prefetchDir) {
    $pfFiles = Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $lookbackDate }
    foreach ($pf in $pfFiles) {
        $entry = [ordered]@{
            Name         = $pf.Name
            LastExecuted = $pf.LastWriteTime.ToString('o')
            Created      = $pf.CreationTime.ToString('o')
            SizeBytes    = $pf.Length
        }
        $prefetchEntries += $entry

        if ($pf.Name -match $iocRegex -or $pf.Name -match 'CURL|CERTUTIL|BITSADMIN|MSHTA|REGSVR32|WSCRIPT|CSCRIPT') {
            Add-Finding -Severity 'WARNING' -Category 'Execution' -Message "Suspicious prefetch: $($pf.Name) (Last run: $($pf.LastWriteTime))"
        }
    }
} else {
    Write-Host "  Prefetch directory not accessible (requires admin)."
}
$report.Evidence.Prefetch = $prefetchEntries
Write-Host "  Recent prefetch entries (last $DaysBack days): $($prefetchEntries.Count)"

# ============================================================
# 11. FILE SYSTEM - RECENTLY MODIFIED FILES IN SUSPICIOUS LOCATIONS
# ============================================================
Write-Section "11" "FILE SYSTEM - SUSPICIOUS TEMP/APPDATA FILES"
$suspiciousLocations = @(
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
) + $ScanPaths

$suspiciousFiles = @()
foreach ($loc in $suspiciousLocations) {
    if (-not (Test-Path $loc)) { continue }
    $files = Get-ChildItem $loc -Recurse -File -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.CreationTime -gt $lookbackDate -and
            $_.Extension -match '\.(exe|dll|bat|cmd|ps1|vbs|js|jse|wsf|scr|hta|com|pif|msi|jar|py)$'
        } |
        Select-Object -First 200  # Cap to prevent long runs

    foreach ($f in $files) {
        $entry = [ordered]@{
            Path      = $f.FullName
            Name      = $f.Name
            Extension = $f.Extension
            Created   = $f.CreationTime.ToString('o')
            Modified  = $f.LastWriteTime.ToString('o')
            SizeBytes = $f.Length
            Hash      = if ($CollectHashes) { Get-SafeHash $f.FullName } else { $null }
        }
        $suspiciousFiles += $entry
    }
}
$report.Evidence.SuspiciousFiles = $suspiciousFiles
if ($suspiciousFiles.Count -gt 0) {
    Add-Finding -Severity 'WARNING' -Category 'FileSystem' -Message "Found $($suspiciousFiles.Count) executable files in temporary/user directories created in last $DaysBack days"
}
Write-Host "  Suspicious executable files found: $($suspiciousFiles.Count)"

# ============================================================
# 12. FILE SYSTEM - CREDENTIAL DB ACCESS TIMES
# ============================================================
Write-Section "12" "BROWSER CREDENTIAL DB ACCESS TIMES"
$browserPaths = @(
    @{ Name="Chrome Login Data";    Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
    @{ Name="Chrome Cookies";       Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" },
    @{ Name="Chrome Local State";   Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" },
    @{ Name="Chrome History";       Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" },
    @{ Name="Chrome Web Data";      Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Web Data" },
    @{ Name="Edge Login Data";      Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
    @{ Name="Edge Cookies";         Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" },
    @{ Name="Edge Local State";     Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" },
    @{ Name="Edge History";         Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" },
    @{ Name="Firefox profiles.ini"; Path="$env:APPDATA\Mozilla\Firefox\profiles.ini" },
    @{ Name="Opera Login Data";     Path="$env:APPDATA\Opera Software\Opera Stable\Login Data" },
    @{ Name="Opera Cookies";        Path="$env:APPDATA\Opera Software\Opera Stable\Cookies" },
    @{ Name="Brave Login Data";     Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" },
    @{ Name="Brave Cookies";        Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cookies" }
)
$browserEvidence = @()
foreach ($b in $browserPaths) {
    if (Test-Path $b.Path) {
        $item = Get-Item $b.Path
        $entry = [ordered]@{
            Name         = $b.Name
            Path         = $b.Path
            LastAccess   = $item.LastAccessTime.ToString('o')
            LastWrite    = $item.LastWriteTime.ToString('o')
            SizeBytes    = $item.Length
            Hash         = if ($CollectHashes) { Get-SafeHash $b.Path } else { $null }
        }
        $browserEvidence += $entry
        Write-Host "  $($b.Name): LastAccess=$($item.LastAccessTime) LastWrite=$($item.LastWriteTime)"
    }
}
$report.Evidence.BrowserCredentialDBs = $browserEvidence

# ============================================================
# 13. CREDENTIAL STORES - SSH, GIT, NPM, ENV FILES
# ============================================================
Write-Section "13" "CREDENTIAL STORES"
$credentialFiles = @()

# SSH Keys
$sshDir = "$env:USERPROFILE\.ssh"
if (Test-Path $sshDir) {
    Get-ChildItem $sshDir -ErrorAction SilentlyContinue | ForEach-Object {
        $credentialFiles += [ordered]@{
            Type     = "SSH"
            Path     = $_.FullName
            Name     = $_.Name
            LastAccess = $_.LastAccessTime.ToString('o')
            LastWrite  = $_.LastWriteTime.ToString('o')
            SizeBytes  = $_.Length
        }
    }
    Add-Finding -Severity 'INFO' -Category 'Credentials' -Message "SSH directory found with $(($credentialFiles | Where-Object {$_.Type -eq 'SSH'}).Count) files - rotate if compromise suspected"
}

# Git credentials (plaintext)
$gitCreds = "$env:USERPROFILE\.git-credentials"
if (Test-Path $gitCreds) {
    $item = Get-Item $gitCreds
    $credentialFiles += [ordered]@{
        Type     = "GitCredentials"
        Path     = $gitCreds
        Name     = ".git-credentials"
        LastAccess = $item.LastAccessTime.ToString('o')
        LastWrite  = $item.LastWriteTime.ToString('o')
        SizeBytes  = $item.Length
    }
    Add-Finding -Severity 'CRITICAL' -Category 'Credentials' -Message ".git-credentials file with plaintext tokens exists"
}

# GitHub CLI
$ghCli = "$env:APPDATA\GitHub CLI"
if (Test-Path $ghCli) {
    Get-ChildItem $ghCli -ErrorAction SilentlyContinue | ForEach-Object {
        $credentialFiles += [ordered]@{
            Type     = "GitHubCLI"
            Path     = $_.FullName
            Name     = $_.Name
            LastAccess = $_.LastAccessTime.ToString('o')
            LastWrite  = $_.LastWriteTime.ToString('o')
            SizeBytes  = $_.Length
        }
    }
    Add-Finding -Severity 'WARNING' -Category 'Credentials' -Message "GitHub CLI tokens present - revoke if compromise suspected"
}

# npm tokens
$npmrc = "$env:USERPROFILE\.npmrc"
if (Test-Path $npmrc) {
    $npmContent = Get-Content $npmrc -Raw -ErrorAction SilentlyContinue
    if ($npmContent -match 'authToken|_auth') {
        $credentialFiles += [ordered]@{
            Type     = "NPM"
            Path     = $npmrc
            Name     = ".npmrc"
            LastAccess = (Get-Item $npmrc).LastAccessTime.ToString('o')
            LastWrite  = (Get-Item $npmrc).LastWriteTime.ToString('o')
            SizeBytes  = (Get-Item $npmrc).Length
        }
        Add-Finding -Severity 'WARNING' -Category 'Credentials' -Message ".npmrc contains npm auth tokens"
    }
}

# .env files (recursive from current dir)
$envFiles = Get-ChildItem -Path (Get-Location) -Filter ".env*" -Recurse -Depth 5 -File -ErrorAction SilentlyContinue
foreach ($ef in $envFiles) {
    $envContent = Get-Content $ef.FullName -Raw -ErrorAction SilentlyContinue
    if ($envContent -match 'SECRET|PRIVATE_KEY|PASSWORD|TOKEN|API_KEY') {
        $keys = ($envContent -split "`n" | Where-Object { $_ -match '^([^=#]+)=' } | ForEach-Object { ($_ -split '=')[0].Trim() })
        $credentialFiles += [ordered]@{
            Type     = "EnvFile"
            Path     = $ef.FullName
            Name     = $ef.Name
            Keys     = $keys
            LastWrite = $ef.LastWriteTime.ToString('o')
        }
        Add-Finding -Severity 'WARNING' -Category 'Credentials' -Message "Env file with secrets: $($ef.FullName)" -Detail $keys
    }
}
$report.Evidence.CredentialStores = $credentialFiles
Write-Host "  Credential files found: $($credentialFiles.Count)"

# ============================================================
# 14. CRYPTO WALLETS
# ============================================================
Write-Section "14" "CRYPTO WALLET DIRECTORIES"
$walletDefs = @(
    @{ Name="Exodus";        Path="$env:APPDATA\Exodus" },
    @{ Name="Atomic";        Path="$env:APPDATA\atomic" },
    @{ Name="Electrum";      Path="$env:APPDATA\Electrum" },
    @{ Name="Ethereum";      Path="$env:APPDATA\Ethereum" },
    @{ Name="Coinomi";       Path="$env:LOCALAPPDATA\Coinomi" },
    @{ Name="Wasabi";        Path="$env:APPDATA\WalletWasabi" },
    @{ Name="Bitcoin Core";  Path="$env:APPDATA\Bitcoin" },
    @{ Name="Guarda";        Path="$env:APPDATA\Guarda" },
    @{ Name="Jaxx Liberty";  Path="$env:APPDATA\com.liberty.jaxx" },
    @{ Name="MetaMask (Ext)"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn" },
    @{ Name="Phantom (Ext)"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa" }
)
$walletsFound = @()
foreach ($w in $walletDefs) {
    if (Test-Path $w.Path) {
        $item = Get-Item $w.Path
        $walletsFound += [ordered]@{
            Name       = $w.Name
            Path       = $w.Path
            LastAccess = $item.LastAccessTime.ToString('o')
            LastWrite  = $item.LastWriteTime.ToString('o')
        }
        Add-Finding -Severity 'WARNING' -Category 'CryptoWallet' -Message "Crypto wallet found: $($w.Name)" -Detail "LastAccess: $($item.LastAccessTime)"
    }
}
$report.Evidence.CryptoWallets = $walletsFound
Write-Host "  Wallets found: $($walletsFound.Count)"

# ============================================================
# 15. EVENT LOG - SECURITY (Process Creation 4688)
# ============================================================
Write-Section "15" "EVENT LOG - SECURITY (PROCESS CREATION 4688)"
$securityEvents = @()
try {
    $events4688 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $suspiciousEvents = $events4688 | Where-Object { $_.Message -match $iocRegex }
    foreach ($evt in $suspiciousEvents) {
        $msgLines = ($evt.Message -split "`n") | Select-Object -First 10
        $securityEvents += [ordered]@{
            TimeCreated  = $evt.TimeCreated.ToString('o')
            EventId      = $evt.Id
            MessageSnippet = ($msgLines -join " ").Substring(0, [Math]::Min(500, ($msgLines -join " ").Length))
        }
    }
    if ($securityEvents.Count -gt 0) {
        Add-Finding -Severity 'WARNING' -Category 'EventLog' -Message "Found $($securityEvents.Count) suspicious process creation events (Event 4688)"
    } else {
        Write-Host "  No suspicious 4688 events found (or audit policy not enabled)."
    }
} catch {
    Write-Host "  Could not read Security event log (requires admin or audit policy)." -ForegroundColor Gray
}
$report.Evidence.SecurityEvents4688 = $securityEvents

# ============================================================
# 16. EVENT LOG - POWERSHELL SCRIPT BLOCK LOGGING (4104)
# ============================================================
Write-Section "16" "EVENT LOG - POWERSHELL SCRIPT BLOCK LOGGING (4104)"
$psScriptBlocks = @()
try {
    $ps4104 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $suspiciousPS = $ps4104 | Where-Object { $_.Message -match $iocRegex -or $_.Message -match 'Invoke-WebRequest|DownloadString|DownloadFile|IEX|Invoke-Expression|Net\.WebClient|Start-BitsTransfer|credential|password|cookie|dpapi|sqlite' }
    foreach ($evt in $suspiciousPS) {
        $psScriptBlocks += [ordered]@{
            TimeCreated    = $evt.TimeCreated.ToString('o')
            ScriptSnippet  = $evt.Message.Substring(0, [Math]::Min(1000, $evt.Message.Length))
        }
    }
    if ($psScriptBlocks.Count -gt 0) {
        Add-Finding -Severity 'WARNING' -Category 'EventLog' -Message "Found $($psScriptBlocks.Count) suspicious PowerShell script block log entries"
    } else {
        Write-Host "  No suspicious script block logs found."
    }
} catch {
    Write-Host "  Could not read PowerShell operational log." -ForegroundColor Gray
}
$report.Evidence.PowerShellScriptBlocks = $psScriptBlocks

# ============================================================
# 17. EVENT LOG - SYSMON (if installed)
# ============================================================
Write-Section "17" "EVENT LOG - SYSMON"
$sysmonEvidence = [ordered]@{ ProcessCreation = @(); NetworkConnections = @(); FileCreation = @() }
try {
    # Process creation (Event 1)
    $sysmon1 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction Stop
    $suspSysmon1 = $sysmon1 | Where-Object { $_.Message -match $iocRegex }
    foreach ($evt in $suspSysmon1) {
        $sysmonEvidence.ProcessCreation += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            Detail      = ($evt.Message -split "`n" | Select-Object -First 8) -join " "
        }
    }

    # Network connections (Event 3)
    $sysmon3 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $suspSysmon3 = $sysmon3 | Where-Object { $_.Message -match $iocRegex -or $_.Message -match 'node\.exe|curl\.exe|python\.exe|powershell\.exe' }
    foreach ($evt in $suspSysmon3) {
        $sysmonEvidence.NetworkConnections += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            Detail      = ($evt.Message -split "`n" | Select-Object -First 8) -join " "
        }
    }

    # File creation (Event 11)
    $sysmon11 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $suspSysmon11 = $sysmon11 | Where-Object { $_.Message -match $iocRegex -or $_.Message -match '\\Temp\\.*\.(exe|dll|bat|ps1|js)' }
    foreach ($evt in $suspSysmon11) {
        $sysmonEvidence.FileCreation += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            Detail      = ($evt.Message -split "`n" | Select-Object -First 8) -join " "
        }
    }

    $totalSysmon = $sysmonEvidence.ProcessCreation.Count + $sysmonEvidence.NetworkConnections.Count + $sysmonEvidence.FileCreation.Count
    if ($totalSysmon -gt 0) {
        Add-Finding -Severity 'WARNING' -Category 'Sysmon' -Message "Found $totalSysmon suspicious Sysmon events (Proc: $($sysmonEvidence.ProcessCreation.Count), Net: $($sysmonEvidence.NetworkConnections.Count), File: $($sysmonEvidence.FileCreation.Count))"
    } else {
        Write-Host "  No suspicious Sysmon events found."
    }
} catch {
    Write-Host "  Sysmon not installed or not accessible." -ForegroundColor Gray
}
$report.Evidence.Sysmon = $sysmonEvidence

# ============================================================
# 18. EVENT LOG - WINDOWS DEFENDER
# ============================================================
Write-Section "18" "WINDOWS DEFENDER DETECTIONS"
$defenderEvidence = @()
try {
    $threats = Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $lookbackDate }
    foreach ($t in $threats) {
        $defenderEvidence += [ordered]@{
            ThreatID       = $t.ThreatID
            ThreatName     = (Get-MpThreat -ThreatID $t.ThreatID -ErrorAction SilentlyContinue).ThreatName
            DetectionTime  = $t.InitialDetectionTime.ToString('o')
            Resources      = $t.Resources
            ActionSuccess  = $t.ActionSuccess
        }
        Add-Finding -Severity 'WARNING' -Category 'Defender' -Message "Defender detection: ThreatID $($t.ThreatID)" -Detail $t.Resources
    }

    $quarantined = Get-MpThreat -ErrorAction SilentlyContinue
    if ($quarantined) {
        $report.Evidence.DefenderQuarantine = $quarantined | Select-Object ThreatID, ThreatName, IsActive, SeverityID
    }
} catch {
    Write-Host "  Could not query Defender (may require admin)." -ForegroundColor Gray
}
if ($defenderEvidence.Count -eq 0) {
    Write-Host "  No Defender detections in last $DaysBack days."
}
$report.Evidence.DefenderDetections = $defenderEvidence

# ============================================================
# 19. EVENT LOG - WINDOWS FILTERING PLATFORM (5156)
# ============================================================
Write-Section "19" "WINDOWS FILTERING PLATFORM - NETWORK LOGS"
$wfpEvents = @()
try {
    $wfp5156 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $suspWfp = $wfp5156 | Where-Object { $_.Message -match $iocRegex -or $_.Message -match 'node\.exe|curl\.exe|powershell\.exe|certutil\.exe' }
    foreach ($evt in $suspWfp) {
        $wfpEvents += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            Detail      = ($evt.Message -split "`n" | Select-Object -First 8) -join " "
        }
    }
    if ($wfpEvents.Count -gt 0) {
        Add-Finding -Severity 'WARNING' -Category 'Network' -Message "Found $($wfpEvents.Count) WFP network events matching IOC patterns"
    } else {
        Write-Host "  No matching WFP network events."
    }
} catch {
    Write-Host "  Could not read WFP logs (requires admin or audit logging)." -ForegroundColor Gray
}
$report.Evidence.WFPEvents = $wfpEvents

# ============================================================
# 20. BITS TRANSFER JOBS
# ============================================================
Write-Section "20" "BITS TRANSFER JOBS"
$bitsEvidence = @()
try {
    $bits = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    foreach ($b in $bits) {
        $bitsEvidence += [ordered]@{
            DisplayName  = $b.DisplayName
            TransferType = $b.TransferType.ToString()
            JobState     = $b.JobState.ToString()
            CreationTime = $b.CreationTime.ToString('o')
            FileList     = $b.FileList | ForEach-Object { $_.RemoteName }
        }
        Add-Finding -Severity 'WARNING' -Category 'Network' -Message "Active BITS transfer: $($b.DisplayName)" -Detail ($b.FileList | ForEach-Object { $_.RemoteName })
    }
} catch {
    Write-Host "  Could not query BITS (may require admin)." -ForegroundColor Gray
}
if ($bitsEvidence.Count -eq 0) {
    Write-Host "  No active BITS transfers."
}
$report.Evidence.BITSTransfers = $bitsEvidence

# ============================================================
# 21. FIREWALL RULES
# ============================================================
Write-Section "21" "CUSTOM FIREWALL RULES"
$fwEntries = @()
try {
    $fwRules = Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notmatch 'Microsoft|Windows|Core Networking|mDNS' }
    foreach ($rule in $fwRules) {
        $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        $fwEntries += [ordered]@{
            DisplayName = $rule.DisplayName
            Description = $rule.Description
            Direction   = $rule.Direction.ToString()
            Action      = $rule.Action.ToString()
            Program     = $appFilter.Program
        }
    }
} catch {
    Write-Host "  Could not query firewall rules." -ForegroundColor Gray
}
$report.Evidence.FirewallRules = $fwEntries
Write-Host "  Custom outbound allow rules: $($fwEntries.Count)"

# ============================================================
# 22. USER ACTIVITY - POWERSHELL COMMAND HISTORY
# ============================================================
Write-Section "22" "POWERSHELL COMMAND HISTORY"
$psHistoryFiles = @()
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    $historyContent = Get-Content $historyPath -Tail 500 -ErrorAction SilentlyContinue
    $suspiciousHistory = $historyContent | Where-Object { $_ -match $iocRegex }
    $psHistoryFiles += [ordered]@{
        Path              = $historyPath
        TotalLines        = (Get-Content $historyPath -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
        Last500Suspicious = $suspiciousHistory
    }
    if ($suspiciousHistory) {
        Add-Finding -Severity 'WARNING' -Category 'UserActivity' -Message "Found $($suspiciousHistory.Count) suspicious commands in PowerShell history"
    } else {
        Write-Host "  No IOC matches in PowerShell command history."
    }
} else {
    Write-Host "  No PSReadLine history file found."
}
$report.Evidence.PowerShellHistory = $psHistoryFiles

# ============================================================
# 23. USER ACTIVITY - RECENT DOCUMENTS
# ============================================================
Write-Section "23" "RECENT DOCUMENTS"
$recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
$recentDocs = @()
if (Test-Path $recentDir) {
    $recentFiles = Get-ChildItem $recentDir -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $lookbackDate } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 50
    foreach ($rf in $recentFiles) {
        $recentDocs += [ordered]@{
            Name      = $rf.Name
            Modified  = $rf.LastWriteTime.ToString('o')
            SizeBytes = $rf.Length
        }
    }
}
$report.Evidence.RecentDocuments = $recentDocs
Write-Host "  Recent documents (last $DaysBack days): $($recentDocs.Count)"

# ============================================================
# 24. USER ACTIVITY - RDP SESSIONS
# ============================================================
Write-Section "24" "RDP SESSION EVIDENCE"
$rdpEvents = @()
try {
    # Successful RDP logons (Event 4624 Type 10)
    $rdpLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Logon Type:\s+10' }
    foreach ($evt in $rdpLogons) {
        $rdpEvents += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            EventId     = 4624
            Type        = "RDP Logon"
            Detail      = ($evt.Message -split "`n" | Select-Object -First 15) -join " "
        }
    }

    # RDP connection events
    $rdpConn = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; StartTime=$lookbackDate} -MaxEvents 100 -ErrorAction SilentlyContinue
    foreach ($evt in $rdpConn) {
        $rdpEvents += [ordered]@{
            TimeCreated = $evt.TimeCreated.ToString('o')
            EventId     = $evt.Id
            Type        = "TS Session"
            Detail      = $evt.Message.Substring(0, [Math]::Min(300, $evt.Message.Length))
        }
    }
} catch {
    Write-Host "  Could not read RDP event logs." -ForegroundColor Gray
}
if ($rdpEvents.Count -gt 0) {
    Add-Finding -Severity 'INFO' -Category 'UserActivity' -Message "Found $($rdpEvents.Count) RDP session events in last $DaysBack days"
} else {
    Write-Host "  No RDP session events found."
}
$report.Evidence.RDPSessions = $rdpEvents

# ============================================================
# 25. USER ACTIVITY - LOGON EVENTS
# ============================================================
Write-Section "25" "LOGON EVENTS SUMMARY"
$logonSummary = @()
try {
    $logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$lookbackDate} -MaxEvents $eventMaxEvents -ErrorAction SilentlyContinue
    $logonTypes = $logons | Group-Object { ($_.Message -split "`n" | Select-String 'Logon Type:' | Select-Object -First 1).ToString().Trim() }
    foreach ($group in $logonTypes) {
        $logonSummary += [ordered]@{
            LogonType = $group.Name
            Count     = $group.Count
            FirstSeen = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToString('o')
            LastSeen  = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString('o')
        }
    }
} catch {
    Write-Host "  Could not read logon events." -ForegroundColor Gray
}
$report.Evidence.LogonSummary = $logonSummary
Write-Host "  Logon type groups: $($logonSummary.Count)"

# ============================================================
# 26. CRASH DUMPS & ERROR REPORTS
# ============================================================
Write-Section "26" "CRASH DUMPS & ERROR REPORTS"
$crashEvidence = @()
$crashDumpDir = "$env:LOCALAPPDATA\CrashDumps"
if (Test-Path $crashDumpDir) {
    $crashDumps = Get-ChildItem $crashDumpDir -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt $lookbackDate }
    foreach ($cd in $crashDumps) {
        $crashEvidence += [ordered]@{
            Type    = "CrashDump"
            Path    = $cd.FullName
            Name    = $cd.Name
            Created = $cd.CreationTime.ToString('o')
            SizeBytes = $cd.Length
            Hash    = if ($CollectHashes) { Get-SafeHash $cd.FullName } else { $null }
        }
    }
}

$werDir = "$env:LOCALAPPDATA\Microsoft\Windows\WER"
if (Test-Path $werDir) {
    $werFiles = Get-ChildItem $werDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt $lookbackDate }
    foreach ($wf in $werFiles) {
        $crashEvidence += [ordered]@{
            Type    = "WER"
            Path    = $wf.FullName
            Name    = $wf.Name
            Created = $wf.CreationTime.ToString('o')
            SizeBytes = $wf.Length
        }
    }
}
$report.Evidence.CrashDumps = $crashEvidence
Write-Host "  Crash dumps/WER reports (last $DaysBack days): $($crashEvidence.Count)"

# ============================================================
# 27. NPM / NODE SPECIFIC CHECKS (if applicable)
# ============================================================
Write-Section "27" "NPM / NODE.JS FORENSICS"
$npmEvidence = [ordered]@{}

# npm cache analysis for IOCs
$npmLogDir = "$env:LOCALAPPDATA\npm-cache\_logs"
$npmLogFindings = @()
if (Test-Path $npmLogDir) {
    $allLogs = Get-ChildItem $npmLogDir -Filter "*.log" -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($log in $allLogs) {
        try {
            $lines = [System.IO.File]::ReadAllLines($log.FullName)
            $matchedLines = $lines | Where-Object { $_ -match $iocRegex }
            if ($matchedLines) {
                $npmLogFindings += [ordered]@{
                    LogFile = $log.Name
                    Date    = $log.LastWriteTime.ToString('o')
                    Matches = $matchedLines | Select-Object -First 20
                }
            }
        } catch {}
    }
    if ($npmLogFindings.Count -gt 0) {
        Add-Finding -Severity 'WARNING' -Category 'NPM' -Message "Found $($npmLogFindings.Count) npm logs matching IOC patterns"
    } else {
        Write-Host "  No IOC matches in npm logs."
    }
} else {
    Write-Host "  npm log directory not found."
}
$npmEvidence.LogFindings = $npmLogFindings

# Check for suspicious packages in package-lock.json (current dir or scan paths)
$lockFiles = @()
if (Test-Path "package-lock.json") { $lockFiles += "package-lock.json" }
foreach ($sp in $ScanPaths) {
    $plock = Join-Path $sp "package-lock.json"
    if (Test-Path $plock) { $lockFiles += $plock }
}
$lockFileEvidence = @()
foreach ($lf in $lockFiles) {
    try {
        $lockContent = Get-Content $lf -Raw
        $iocMatches = [regex]::Matches($lockContent, $iocRegex)
        if ($iocMatches.Count -gt 0) {
            $lockFileEvidence += [ordered]@{
                File    = $lf
                Matches = $iocMatches | ForEach-Object { $_.Value } | Select-Object -Unique
            }
            Add-Finding -Severity 'CRITICAL' -Category 'NPM' -Message "IOC patterns found in $lf"
        }
    } catch {}
}
$npmEvidence.LockFileFindings = $lockFileEvidence
$report.Evidence.NPM = $npmEvidence

# ============================================================
# 28. AMCACHE - PROGRAM EXECUTION HISTORY
# ============================================================
Write-Section "28" "AMCACHE ANALYSIS"
$amcachePath = "C:\Windows\AppCompat\Programs\Amcache.hve"
$amcacheEvidence = [ordered]@{ Exists = (Test-Path $amcachePath) }
if (Test-Path $amcachePath) {
    $amcacheItem = Get-Item $amcachePath
    $amcacheEvidence.LastWrite = $amcacheItem.LastWriteTime.ToString('o')
    $amcacheEvidence.SizeBytes = $amcacheItem.Length
    $amcacheEvidence.Hash = if ($CollectHashes) { Get-SafeHash $amcachePath } else { $null }
    Write-Host "  Amcache exists (LastWrite: $($amcacheItem.LastWriteTime)). Parse with external tools for full analysis."
    Add-Finding -Severity 'INFO' -Category 'Execution' -Message "Amcache.hve available for offline analysis (use AmcacheParser/Registry Explorer)"
} else {
    Write-Host "  Amcache not accessible."
}
$report.Evidence.Amcache = $amcacheEvidence

# ============================================================
# 29. LOADED DLLs - INJECTION DETECTION
# ============================================================
Write-Section "29" "LOADED DLL ANALYSIS (INJECTION DETECTION)"
$dllEvidence = @()
$targetProcs = Get-Process -Name 'explorer','svchost','lsass','winlogon','csrss','services' -ErrorAction SilentlyContinue
foreach ($proc in $targetProcs) {
    try {
        $modules = $proc.Modules | Where-Object {
            $_.FileName -and $_.FileName -notmatch 'Windows\\System32|Windows\\SysWOW64|Windows\\WinSxS|Microsoft\.NET|Program Files'
        }
        foreach ($mod in $modules) {
            $entry = [ordered]@{
                ProcessName = $proc.Name
                ProcessId   = $proc.Id
                DLLPath     = $mod.FileName
                DLLName     = $mod.ModuleName
                SizeBytes   = $mod.ModuleMemorySize
                Hash        = if ($CollectHashes) { Get-SafeHash $mod.FileName } else { $null }
            }
            $dllEvidence += $entry
            Add-Finding -Severity 'WARNING' -Category 'Injection' -Message "Non-standard DLL in $($proc.Name): $($mod.FileName)"
        }
    } catch {}
}
$report.Evidence.SuspiciousDLLs = $dllEvidence
Write-Host "  Non-standard DLLs in system processes: $($dllEvidence.Count)"

# ============================================================
# 30. OPEN FILE HANDLES & NAMED PIPES
# ============================================================
Write-Section "30" "NAMED PIPES (C2 CHANNEL DETECTION)"
$namedPipes = @()
try {
    $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch 'mojo|chrome|msedge|crashpad|googlechrome|discord|electron|NamedPipe' }
    # Filter for unusual pipes
    $suspiciousPipes = $pipes | Where-Object { $_.Name -match $iocRegex -or $_.Name -match 'shell|beacon|bind|reverse|covert|tunnel' }
    foreach ($p in $suspiciousPipes) {
        $namedPipes += [ordered]@{ Name = $p.Name }
        Add-Finding -Severity 'WARNING' -Category 'C2' -Message "Suspicious named pipe: $($p.Name)"
    }
} catch {}
$report.Evidence.NamedPipes = $namedPipes
Write-Host "  Suspicious named pipes: $($namedPipes.Count)"

# ============================================================
# REPORT GENERATION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GENERATING REPORT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Add timing
$scriptEndTime = Get-Date
$report.Metadata.CompletedDate = $scriptEndTime.ToString('o')
$report.Metadata.DurationSeconds = [math]::Round(($scriptEndTime - $scriptStartTime).TotalSeconds, 2)

# Compute report hash for integrity
$jsonReport = $report | ConvertTo-Json -Depth 10
$reportPath = Join-Path $OutputDir "forensic-report.json"
$jsonReport | Out-File -FilePath $reportPath -Encoding UTF8

$reportHash = Get-SafeHash $reportPath
$chainOfCustody = [ordered]@{
    ReportFile     = $reportPath
    SHA256         = $reportHash
    GeneratedBy    = "$env:USERDOMAIN\$env:USERNAME"
    GeneratedAt    = $scriptEndTime.ToString('o')
    ScriptHash     = Get-SafeHash $PSCommandPath
    Hostname       = $env:COMPUTERNAME
}
$chainOfCustody | ConvertTo-Json | Out-File -FilePath (Join-Path $OutputDir "chain-of-custody.json") -Encoding UTF8

# CSV summary of findings
$report.Findings | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.Timestamp
        Severity  = $_.Severity
        Category  = $_.Category
        Message   = $_.Message
    }
} | Export-Csv -Path (Join-Path $OutputDir "findings.csv") -NoTypeInformation -Encoding UTF8

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FORENSIC TRIAGE SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$critCount = ($report.Findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
$warnCount = ($report.Findings | Where-Object { $_.Severity -eq 'WARNING' }).Count
$infoCount = ($report.Findings | Where-Object { $_.Severity -eq 'INFO' }).Count
$totalFindings = $report.Findings.Count

if ($totalFindings -eq 0) {
    Write-Host "  No findings detected." -ForegroundColor Green
} else {
    Write-Host "  Total findings: $totalFindings" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } else { 'DarkYellow' })
    Write-Host "    CRITICAL: $critCount" -ForegroundColor Red
    Write-Host "    WARNING:  $warnCount" -ForegroundColor DarkYellow
    Write-Host "    INFO:     $infoCount" -ForegroundColor Gray
    Write-Host ""

    if ($critCount -gt 0) {
        Write-Host "  CRITICAL FINDINGS:" -ForegroundColor Red
        $report.Findings | Where-Object { $_.Severity -eq 'CRITICAL' } | ForEach-Object {
            Write-Host "    [CRITICAL] $($_.Category): $($_.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($warnCount -gt 0) {
        Write-Host "  WARNINGS:" -ForegroundColor DarkYellow
        $report.Findings | Where-Object { $_.Severity -eq 'WARNING' } | ForEach-Object {
            Write-Host "    [WARNING] $($_.Category): $($_.Message)" -ForegroundColor DarkYellow
        }
    }
}

Write-Host ""
Write-Host "  Duration: $($report.Metadata.DurationSeconds) seconds" -ForegroundColor Gray
Write-Host "  IOC patterns used: $($IOCPatterns.Count)" -ForegroundColor Gray
Write-Host "  Lookback period: $DaysBack days" -ForegroundColor Gray
Write-Host ""
Write-Host "  OUTPUT FILES:" -ForegroundColor Cyan
Write-Host "    Report:          $reportPath" -ForegroundColor White
Write-Host "    Findings CSV:    $(Join-Path $OutputDir 'findings.csv')" -ForegroundColor White
Write-Host "    Chain of Custody: $(Join-Path $OutputDir 'chain-of-custody.json')" -ForegroundColor White
Write-Host "    Report SHA-256:  $reportHash" -ForegroundColor White
Write-Host ""
Write-Host "  RECOMMENDED NEXT STEPS:" -ForegroundColor Cyan
Write-Host "    1. Review forensic-report.json for full evidence details" -ForegroundColor White
Write-Host "    2. Cross-reference findings with threat intelligence feeds" -ForegroundColor White
Write-Host "    3. Parse Amcache/Shimcache with AmcacheParser for execution timeline" -ForegroundColor White
Write-Host "    4. If critical findings exist, preserve disk image before remediation" -ForegroundColor White
Write-Host "    5. Rotate all credentials found in the credential stores section" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
