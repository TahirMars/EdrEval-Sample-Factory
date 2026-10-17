#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Configures a Windows 10/11 x64 guest for EdrEval factory validation management.

.DESCRIPTION
Run this script inside the guest from an elevated Windows PowerShell 5.1 session.
It preserves the existing NAT configuration, validates the expected guest IP,
creates EdrEval directories and a dedicated local account, adds that account
to Administrators while leaving UAC enabled, enables console auto-logon, and
registers a logon-time interactive worker so Harness EXEs run on the user
desktop (Session > 0, RunLevel Limited = medium integrity split token) instead
of WinRM Session 0. WinRM HTTPS remains the management channel and is
restricted to the specified management-host IPv4 address. Elevation TTPs start
from this filtered administrator, not from a true standard user and not from a
high-integrity process. This snapshot is not the factory D8 standard-user
band. This script does not disable Defender, clear system event logs, disable
UAC, or claim that NAT provides isolation or verified snapshot rollback.

.PARAMETER ManagementHostIp
The VMware VMnet8 IPv4 address of the validation host. Determine this on the
host before running the script; do not use the NAT gateway address.

.PARAMETER ExpectedVmIp
The IPv4 address already assigned to this VM. The script validates but never
changes it. The default is 192.168.131.139.

.PARAMETER CleanApplicationState
Deletes only existing content below the EdrEval Runs, SampleLogs, and Evidence
directories. It never clears Windows event logs.

.PARAMETER DeclareNoCommercialEdr
Records an explicit operator assertion that no commercial EDR is installed.
This switch does not disable or reconfigure Defender or any security product.

.EXAMPLE
.\configure_factory_validation_vm.ps1 -ManagementHostIp 192.168.131.1 -CleanApplicationState -DeclareNoCommercialEdr

Use the actual VMware VMnet8 host address instead of assuming the example
address is correct.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress]$ManagementHostIp,

    [System.Net.IPAddress]$ExpectedVmIp = "192.168.131.139",

    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$VmDnsName = "new-dev.edreval.lab",

    [ValidatePattern('^[A-Za-z0-9_.-]{1,20}$')]
    [string]$RunnerUser = "edreval_runner",

    [switch]$ResetRunnerPassword,
    [switch]$PasswordNeverExpires,
    [switch]$CleanApplicationState,
    [switch]$DeclareNoCommercialEdr,
    [switch]$ReplaceHttpsListener
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProductRoot = "C:\ProgramData\EdrEvalAgent"
$RunsRoot = Join-Path $ProductRoot "Runs"
$LogsRoot = Join-Path $ProductRoot "SampleLogs"
$EvidenceRoot = Join-Path $ProductRoot "Evidence"
$BootstrapRoot = Join-Path $ProductRoot "Bootstrap"
$FirewallRuleName = "EdrEval-WinRM-HTTPS"
$ExpectedVmIpText = $ExpectedVmIp.IPAddressToString
$ManagementHostIpText = $ManagementHostIp.IPAddressToString

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[EdrEval VM Setup] $Message"
}

function Set-DirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$RunnerSid,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$RunnerRights
    )

    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $adminsSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
    )
    $acl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $adminsSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
    )
    $acl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $RunnerSid,
            $RunnerRights,
            $inheritance,
            $propagation,
            $allow
        )
    )
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-ServiceState {
    param([Parameter(Mandatory = $true)][string]$NamePattern)
    $services = @(Get-Service -Name $NamePattern -ErrorAction SilentlyContinue)
    if ($services.Count -eq 0) {
        return [ordered]@{
            found = $false
            names = @()
            states = @()
        }
    }
    return [ordered]@{
        found = $true
        names = @($services | ForEach-Object { $_.Name })
        states = @($services | ForEach-Object { $_.Status.ToString() })
    }
}

function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory = $true)][SecureString]$Secret)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Ensure-RunnerAccount {
    param([Parameter(Mandatory = $true)][string]$Name)

    $password = $null
    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $user) {
        Write-Step "Creating dedicated local account '$Name' (Administrators + UAC split token)."
        $password = Read-Host "Enter the dedicated lab password for $Name" -AsSecureString
        $user = New-LocalUser `
            -Name $Name `
            -Password $password `
            -AccountNeverExpires `
            -PasswordNeverExpires:$PasswordNeverExpires `
            -Description "EdrEval factory validation management account"
    }
    elseif ($ResetRunnerPassword) {
        Write-Step "Resetting the password for '$Name' without logging it."
        $password = Read-Host "Enter the new dedicated lab password for $Name" -AsSecureString
        Set-LocalUser `
            -Name $Name `
            -Password $password `
            -PasswordNeverExpires:$PasswordNeverExpires
        $user = Get-LocalUser -Name $Name
    }
    else {
        Write-Step "Account '$Name' already exists; password was not changed."
        if ($PasswordNeverExpires -and -not $user.PasswordNeverExpires) {
            Set-LocalUser -Name $Name -PasswordNeverExpires $true
            $user = Get-LocalUser -Name $Name
        }
        $password = Read-Host "Enter the existing lab password for $Name (console auto-logon)" -AsSecureString
    }

    if (-not $user.Enabled) {
        Enable-LocalUser -Name $Name
        $user = Get-LocalUser -Name $Name
    }

    $remoteManagementGroup = Get-LocalGroup -SID "S-1-5-32-580"
    $isMember = @(
        Get-LocalGroupMember -Group $remoteManagementGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -eq $user.SID }
    ).Count -gt 0
    if (-not $isMember) {
        Add-LocalGroupMember -Group $remoteManagementGroup -Member $user
    }
    $eventLogReadersGroup = Get-LocalGroup -SID "S-1-5-32-573"
    $canReadEvents = @(
        Get-LocalGroupMember -Group $eventLogReadersGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -eq $user.SID }
    ).Count -gt 0
    if (-not $canReadEvents) {
        Add-LocalGroupMember -Group $eventLogReadersGroup -Member $user
    }
    $adminsGroup = Get-LocalGroup -SID "S-1-5-32-544"
    $isAdmin = @(
        Get-LocalGroupMember -Group $adminsGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -eq $user.SID }
    ).Count -gt 0
    if (-not $isAdmin) {
        Write-Step "Adding '$Name' to Administrators; interactive worker stays RunLevel Limited."
        Add-LocalGroupMember -Group $adminsGroup -Member $user
    }
    return [pscustomobject]@{
        User = $user
        Password = $password
    }
}

function Enable-InteractiveAutoLogon {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][SecureString]$Password
    )
    Write-Step "Enabling console auto-logon for '$UserName' (filtered local admin, UAC left enabled)."
    $plain = ConvertFrom-SecureStringPlain -Secret $Password
    try {
        $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -LiteralPath $winlogon -Name "AutoAdminLogon" -Value "1"
        Set-ItemProperty -LiteralPath $winlogon -Name "ForceAutoLogon" -Value "1"
        Set-ItemProperty -LiteralPath $winlogon -Name "DefaultUserName" -Value $UserName
        Set-ItemProperty -LiteralPath $winlogon -Name "DefaultDomainName" -Value $env:COMPUTERNAME
        Set-ItemProperty -LiteralPath $winlogon -Name "DefaultPassword" -Value $plain
    }
    finally {
        $plain = $null
    }
}

function Install-InteractiveWorker {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$WorkerPath,
        [Parameter(Mandatory = $true)][string]$RunsRoot,
        [Parameter(Mandatory = $true)][string]$HeartbeatPath
    )
    Write-Step "Installing the interactive desktop worker (Session > 0, RunLevel Limited)."
    $runsRootLiteral = $RunsRoot.Replace("'", "''")
    $heartbeatLiteral = $HeartbeatPath.Replace("'", "''")
    $worker = @"
#Requires -Version 5.1
Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"
`$RunsRoot = '$runsRootLiteral'
`$HeartbeatPath = '$heartbeatLiteral'

function Test-UnderRunsRoot {
    param([Parameter(Mandatory = `$true)][string]`$Candidate)
    `$full = [System.IO.Path]::GetFullPath(`$Candidate)
    `$root = [System.IO.Path]::GetFullPath(`$RunsRoot).TrimEnd('\') + '\'
    return `$full.StartsWith(`$root, [StringComparison]::OrdinalIgnoreCase)
}

function Write-Heartbeat {
    `$dir = Split-Path -Parent `$HeartbeatPath
    if (-not (Test-Path -LiteralPath `$dir)) {
        New-Item -ItemType Directory -Path `$dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText(
        `$HeartbeatPath,
        [DateTime]::UtcNow.ToString("o")
    )
}

function Invoke-LaunchRequest {
    param([Parameter(Mandatory = `$true)][string]`$RequestPath)
    `$resultPath = Join-Path (Split-Path -Parent `$RequestPath) "launch-result.json"
    `$started = [DateTime]::UtcNow
    `$created = `$false
    `$pidValue = `$null
    `$exitCode = `$null
    `$timedOut = `$false
    `$errorText = `$null
    `$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    try {
        if (`$sessionId -le 0) {
            throw "Interactive worker is in Session 0; refusing to start Harness."
        }
        `$request = Get-Content -LiteralPath `$RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (`$request.schema_version -ne "factory-vmware-interactive-launch-v1") {
            throw "Unsupported interactive launch schema."
        }
        `$artifact = [System.IO.Path]::GetFullPath([string]`$request.artifact_path)
        if (-not (Test-UnderRunsRoot -Candidate `$artifact)) {
            throw "Launch artifact is outside the Runs root."
        }
        if (-not `$artifact.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Launch artifact must be an .exe."
        }
        if (-not (Test-Path -LiteralPath `$artifact -PathType Leaf)) {
            throw "Launch artifact does not exist."
        }
        `$timeoutMs = [int]`$request.timeout_ms
        if (`$timeoutMs -lt 1000) {
            `$timeoutMs = 1000
        }
        `$workDir = [IO.Path]::GetDirectoryName(`$artifact)
        `$process = Start-Process -FilePath `$artifact -WorkingDirectory `$workDir -PassThru
        `$created = `$true
        `$pidValue = `$process.Id
        `$sessionId = `$process.SessionId
        if (`$sessionId -le 0) {
            & taskkill.exe /PID `$process.Id /T /F 2>&1 | Out-Null
            throw "Harness started in Session 0; killed."
        }
        if (-not `$process.WaitForExit(`$timeoutMs)) {
            `$timedOut = `$true
            & taskkill.exe /PID `$process.Id /T /F 2>&1 | Out-Null
            `$process.WaitForExit()
        }
        else {
            `$exitCode = `$process.ExitCode
        }
    }
    catch {
        `$errorText = "{0}: {1}" -f `$_.Exception.GetType().FullName, `$_.Exception.Message
    }
    `$result = [ordered]@{
        schema_version = "factory-vmware-interactive-launch-result-v1"
        process_created = [bool]`$created
        process_id = `$pidValue
        session_id = `$sessionId
        exit_code = `$exitCode
        timed_out = [bool]`$timedOut
        error = `$errorText
        started_at_utc = `$started.ToString("o")
        finished_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    `$tmpPath = `$resultPath + ".tmp"
    `$result | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath `$tmpPath -Encoding UTF8
    Move-Item -LiteralPath `$tmpPath -Destination `$resultPath -Force
    Move-Item -LiteralPath `$RequestPath -Destination (`$RequestPath + ".done") -Force
}

Write-Heartbeat
while (`$true) {
    Write-Heartbeat
    `$requests = @(
        Get-ChildItem -LiteralPath `$RunsRoot -Filter "launch-request.json" -File -Recurse -ErrorAction SilentlyContinue
    )
    foreach (`$requestFile in `$requests) {
        Invoke-LaunchRequest -RequestPath `$requestFile.FullName
    }
    Start-Sleep -Milliseconds 400
}
"@
    Set-Content -LiteralPath $WorkerPath -Value $worker -Encoding UTF8

    $taskName = "EdrEvalInteractiveWorker"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$WorkerPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
    $principal = New-ScheduledTaskPrincipal `
        -UserId $UserName `
        -LogonType Interactive `
        -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

function Remove-WinRmHttpSurface {
    Write-Step "Removing WinRM HTTP listeners and disabling default HTTP firewall rules."
    $httpListeners = @(
        Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
            Where-Object { ($_.Keys -join " ") -match 'Transport=HTTP(?:\s|$)' }
    )
    foreach ($listener in $httpListeners) {
        Remove-Item -LiteralPath $listener.PSPath -Recurse -Force
    }

    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "WINRM-HTTP-In-TCP*" } |
        Disable-NetFirewallRule | Out-Null
}

function Get-ListenerThumbprint {
    param([Parameter(Mandatory = $true)]$Listener)
    $value = Get-ChildItem -LiteralPath $Listener.PSPath |
        Where-Object { $_.Name -eq "CertificateThumbprint" } |
        Select-Object -First 1
    if ($null -eq $value) {
        return ""
    }
    return [string]$value.Value
}

function Ensure-WinRmHttps {
    Write-Step "Configuring WinRM HTTPS. NAT configuration is preserved."
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
    Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
    Remove-WinRmHttpSurface

    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true

    $validAfter = (Get-Date).AddDays(30)
    $certificate = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.Subject -eq "CN=$VmDnsName" -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt $validAfter
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($null -eq $certificate) {
        Write-Step "Creating a non-exportable WinRM server certificate for $VmDnsName."
        $certificate = New-SelfSignedCertificate `
            -DnsName @($VmDnsName, $env:COMPUTERNAME) `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -Type SSLServerAuthentication `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddYears(3)
    }

    $httpsListeners = @(
        Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
            Where-Object { ($_.Keys -join " ") -match 'Transport=HTTPS(?:\s|$)' }
    )
    $listenerMatches = $false
    foreach ($listener in $httpsListeners) {
        if ((Get-ListenerThumbprint -Listener $listener) -eq $certificate.Thumbprint) {
            $listenerMatches = $true
        }
    }

    if ($httpsListeners.Count -gt 0 -and -not $listenerMatches) {
        if (-not $ReplaceHttpsListener) {
            throw (
                "An HTTPS WinRM listener already exists with another certificate. " +
                "Review it, then rerun with -ReplaceHttpsListener if replacement is intended."
            )
        }
        foreach ($listener in $httpsListeners) {
            Remove-Item -LiteralPath $listener.PSPath -Recurse -Force
        }
        $httpsListeners = @()
    }

    if (-not $listenerMatches) {
        New-Item `
            -Path WSMan:\localhost\Listener `
            -Transport HTTPS `
            -Address "*" `
            -CertificateThumbPrint $certificate.Thumbprint `
            -Force | Out-Null
    }

    $existingRule = Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        Remove-NetFirewallRule -Name $FirewallRuleName
    }
    New-NetFirewallRule `
        -Name $FirewallRuleName `
        -DisplayName "EdrEval WinRM HTTPS from validation host" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalAddress $ExpectedVmIpText `
        -LocalPort 5986 `
        -RemoteAddress $ManagementHostIpText `
        -Profile Any | Out-Null

    $certificatePath = Join-Path $BootstrapRoot "winrm-server.cer"
    Export-Certificate `
        -Cert $certificate `
        -FilePath $certificatePath `
        -Type CERT `
        -Force | Out-Null

    $trustedCertificate = Get-ChildItem `
        -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)" `
        -ErrorAction SilentlyContinue
    if ($null -eq $trustedCertificate) {
        Import-Certificate `
            -FilePath $certificatePath `
            -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    }

    Test-WSMan -ComputerName $env:COMPUTERNAME -UseSSL -ErrorAction Stop | Out-Null
    return [ordered]@{
        thumbprint = $certificate.Thumbprint
        subject = $certificate.Subject
        not_after = $certificate.NotAfter.ToUniversalTime().ToString("o")
        exported_certificate = $certificatePath
    }
}

Write-Step "Validating the requested management and VM addresses."
if ($ManagementHostIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "ManagementHostIp must be an IPv4 address."
}
if ($ExpectedVmIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "ExpectedVmIp must be an IPv4 address."
}
if ($ManagementHostIpText -eq $ExpectedVmIpText) {
    throw "ManagementHostIp and ExpectedVmIp must be different."
}

$matchingAddress = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
        $_.IPAddress -eq $ExpectedVmIpText -and
        $_.AddressState -eq "Preferred"
    } |
    Select-Object -First 1
if ($null -eq $matchingAddress) {
    $activeAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq "Preferred" } |
            ForEach-Object { $_.IPAddress }
    )
    throw (
        "Expected VM IP $ExpectedVmIpText is not active. Active IPv4 addresses: " +
        ($activeAddresses -join ", ") +
        ". This script does not change network configuration."
    )
}

Write-Step "Validating Windows 10/11 x64."
$operatingSystem = Get-CimInstance Win32_OperatingSystem
if ($operatingSystem.Caption -notmatch "Windows (10|11)") {
    throw "Expected Windows 10 or Windows 11, found '$($operatingSystem.Caption)'."
}
if ($operatingSystem.OSArchitecture -notmatch "64") {
    throw "Expected a 64-bit guest, found '$($operatingSystem.OSArchitecture)'."
}

Write-Step "Creating EdrEval application directories."
@($ProductRoot, $RunsRoot, $LogsRoot, $EvidenceRoot, $BootstrapRoot) |
    ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

if ($CleanApplicationState) {
    Write-Step "Cleaning only EdrEval-owned Runs, SampleLogs, and Evidence content."
    foreach ($directory in @($RunsRoot, $LogsRoot, $EvidenceRoot)) {
        Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force
    }
}

$runnerProvision = Ensure-RunnerAccount -Name $RunnerUser
$runnerAccount = $runnerProvision.User
Enable-InteractiveAutoLogon -UserName $RunnerUser -Password $runnerProvision.Password
$runnerProvision.Password = $null
$InteractiveWorkerPath = Join-Path $BootstrapRoot "interactive-worker.ps1"
$InteractiveHeartbeatPath = Join-Path $LogsRoot "interactive-worker.heartbeat"
Install-InteractiveWorker `
    -UserName $RunnerUser `
    -WorkerPath $InteractiveWorkerPath `
    -RunsRoot $RunsRoot `
    -HeartbeatPath $InteractiveHeartbeatPath
Write-Step "Applying least-privilege directory ACLs."
Set-DirectoryAcl `
    -Path $ProductRoot `
    -RunnerSid $runnerAccount.SID `
    -RunnerRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
foreach ($directory in @($RunsRoot, $LogsRoot, $EvidenceRoot)) {
    Set-DirectoryAcl `
        -Path $directory `
        -RunnerSid $runnerAccount.SID `
        -RunnerRights ([System.Security.AccessControl.FileSystemRights]::Modify)
}
Set-DirectoryAcl `
    -Path $BootstrapRoot `
    -RunnerSid $runnerAccount.SID `
    -RunnerRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)

$winRmCertificate = Ensure-WinRmHttps
$vmwareTools = Get-ServiceState -NamePattern "VMTools"
$sysmon = Get-ServiceState -NamePattern "Sysmon*"
$winRm = Get-ServiceState -NamePattern "WinRM"
$defender = $null
try {
    $defenderState = Get-MpComputerStatus -ErrorAction Stop
    $defender = [ordered]@{
        available = $true
        antivirus_enabled = [bool]$defenderState.AntivirusEnabled
        real_time_protection_enabled = [bool]$defenderState.RealTimeProtectionEnabled
    }
}
catch {
    $defender = [ordered]@{
        available = $false
        antivirus_enabled = $null
        real_time_protection_enabled = $null
    }
}

$sysmonReady = $sysmon.found -and ($sysmon.states -contains "Running")
$vmwareToolsReady = $vmwareTools.found -and ($vmwareTools.states -contains "Running")
$profile = [ordered]@{
    schema_version = "edreval-factory-vm-bootstrap-v1"
    recorded_at_utc = [DateTime]::UtcNow.ToString("o")
    host_name = $env:COMPUTERNAME
    vm_dns_name = $VmDnsName
    os = [ordered]@{
        caption = $operatingSystem.Caption
        version = $operatingSystem.Version
        architecture = $operatingSystem.OSArchitecture
    }
    network = [ordered]@{
        declared_mode = "nat"
        vm_ip = $ExpectedVmIpText
        management_host_ip = $ManagementHostIpText
        interface_alias = $matchingAddress.InterfaceAlias
        isolated = $false
    }
    management = [ordered]@{
        runner_user = $RunnerUser
        runner_local_admin = $true
        execution_integrity = "medium"
        interactive_worker_run_level = "Limited"
        execution_session = "interactive_console"
        interactive_worker_task = "EdrEvalInteractiveWorker"
        winrm_https_port = 5986
        allow_unencrypted = $false
        basic_auth = $false
        certificate = $winRmCertificate
    }
    services = [ordered]@{
        vmware_tools = $vmwareTools
        winrm = $winRm
        sysmon = $sysmon
    }
    security_product = [ordered]@{
        defender = $defender
        declared_no_edr = [bool]$DeclareNoCommercialEdr
        declaration_kind = if ($DeclareNoCommercialEdr) {
            "operator-asserted-no-commercial-edr"
        }
        else {
            "not-declared"
        }
    }
    directories = [ordered]@{
        runs = $RunsRoot
        sample_logs = $LogsRoot
        evidence = $EvidenceRoot
    }
    readiness = [ordered]@{
        guest_management_ready = $true
        vmware_tools_ready = $vmwareToolsReady
        sensors_ready = $sysmonReady
        snapshot_candidate = "new_dev_v2"
        snapshot_rollback_verified = $false
        rollback_capable = $false
    }
}

$profilePath = Join-Path $BootstrapRoot "vm-profile.json"
$profile | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $profilePath -Encoding UTF8

Write-Step "Configuration complete."
Write-Host "Profile report: $profilePath"
Write-Host "Public WinRM certificate: $($winRmCertificate.exported_certificate)"
Write-Host "NAT remains enabled; this VM is recorded as isolated=false."
if (-not $vmwareToolsReady) {
    Write-Warning "VMware Tools is missing or not running. Install/fix it before snapshot testing."
}
if (-not $sysmonReady) {
    Write-Warning "Sysmon is missing or not running. sensors_ready remains false."
}
Write-Host (
    "Next: log off and auto-logon as $RunnerUser so the interactive session receives the " +
    "split token and the Limited desktop worker is running, trust the exported certificate " +
    "on the validation host, map $VmDnsName to $ExpectedVmIpText, test WinRM from " +
    "$ManagementHostIpText, then snapshot new_dev_v2 while the runner desktop session is logged on."
)
