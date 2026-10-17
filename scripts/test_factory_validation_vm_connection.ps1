#Requires -Version 5.1

<#
.SYNOPSIS
Tests the EdrEval WinRM HTTPS management path from the validation host to a VM.

.DESCRIPTION
Run this script on the validation host. It verifies the VM bootstrap profile and
public certificate, resolves the expected VM address, tests TCP 5986 and WinRM,
uploads a unique probe as a .part file, verifies SHA-256 in the guest, atomically
renames it, downloads it, and verifies the round-trip SHA-256. Only the probe
directories created by this invocation are removed.

.PARAMETER ConfigureHostTrust
Explicitly permits this script to add a missing hosts entry and import the
verified public certificate into LocalMachine Root. This requires elevation.

.EXAMPLE
.\test_factory_validation_vm_connection.ps1 -CertificatePath C:\Temp\winrm-server.cer -ProfilePath C:\Temp\vm-profile.json -ConfigureHostTrust
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CertificatePath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ProfilePath,

    [System.Net.IPAddress]$VmIp = "192.168.131.180",

    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$VmDnsName = "new-dev.edreval.lab",

    [ValidatePattern('^[A-Za-z0-9_.-]{1,20}$')]
    [string]$RunnerUser = "edreval_runner",

    [System.Management.Automation.PSCredential]$Credential,
    [switch]$ConfigureHostTrust
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$VmIpText = $VmIp.IPAddressToString
$CertificatePath = (Resolve-Path -LiteralPath $CertificatePath).Path
$ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
$HostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$RemoteRunsRoot = "C:\ProgramData\EdrEvalAgent\Runs"
$RemoteLogsRoot = "C:\ProgramData\EdrEvalAgent\SampleLogs"
$ProbeId = [guid]::NewGuid().ToString("N")
$RemoteProbeRoot = Join-Path $RemoteRunsRoot "connectivity-$ProbeId"
$RemotePartPath = Join-Path $RemoteProbeRoot "probe.txt.part"
$RemoteFinalPath = Join-Path $RemoteProbeRoot "probe.txt"
$LocalProbeRoot = Join-Path ([System.IO.Path]::GetTempPath()) "edreval-$ProbeId"
$LocalProbePath = Join-Path $LocalProbeRoot "probe.txt"
$RoundTripPath = Join-Path $LocalProbeRoot "probe-roundtrip.txt"
$Session = $null

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[EdrEval VM Test] $Message"
}

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Add-HostMappingIfMissing {
    $escapedName = [regex]::Escape($VmDnsName)
    $activePattern = "(?i)^\s*[^#\s]+(?:\s+[^#\s]+)*\s+$escapedName(?:\s|$)"
    $lines = @(Get-Content -LiteralPath $HostsPath -ErrorAction Stop)
    $existing = @($lines | Where-Object { $_ -match $activePattern })
    if ($existing.Count -gt 0) {
        $escapedIp = [regex]::Escape($VmIpText)
        $expectedPattern = "(?i)^\s*$escapedIp\s+.*(?:^|\s)$escapedName(?:\s|$)"
        if (@($existing | Where-Object { $_ -match $expectedPattern }).Count -eq 0) {
            throw (
                "The hosts file already maps $VmDnsName to another address. " +
                "Review it manually; this script will not replace an existing mapping."
            )
        }
        return
    }
    Add-Content -LiteralPath $HostsPath -Value "$VmIpText $VmDnsName" -Encoding ASCII
}

function Import-VerifiedCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $trustedPath = "Cert:\LocalMachine\Root\$($Certificate.Thumbprint)"
    if (-not (Test-Path -LiteralPath $trustedPath)) {
        $importParams = @{
            FilePath = $CertificatePath
            CertStoreLocation = "Cert:\LocalMachine\Root"
        }
        Import-Certificate @importParams | Out-Null
    }
}

Write-Step "Loading and validating the VM profile and public certificate."
$Profile = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Profile.schema_version -ne "edreval-factory-vm-bootstrap-v1") {
    throw "Unsupported VM profile schema '$($Profile.schema_version)'."
}
if ($Profile.network.vm_ip -ne $VmIpText) {
    throw "Profile VM IP '$($Profile.network.vm_ip)' does not match '$VmIpText'."
}
if ($Profile.vm_dns_name -ne $VmDnsName) {
    throw "Profile DNS name '$($Profile.vm_dns_name)' does not match '$VmDnsName'."
}

$Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $CertificatePath
)
$ExpectedThumbprint = ([string]$Profile.management.certificate.thumbprint).ToUpperInvariant()
if ($Certificate.Thumbprint.ToUpperInvariant() -ne $ExpectedThumbprint) {
    throw "Certificate thumbprint does not match vm-profile.json."
}
if ($Certificate.Subject -ne "CN=$VmDnsName") {
    throw "Certificate subject '$($Certificate.Subject)' does not match CN=$VmDnsName."
}
$Now = Get-Date
if ($Now -lt $Certificate.NotBefore -or $Now -gt $Certificate.NotAfter) {
    throw "The VM WinRM certificate is not currently valid."
}

if ($ConfigureHostTrust) {
    if (-not (Test-IsAdministrator)) {
        throw "-ConfigureHostTrust requires an elevated PowerShell session."
    }
    Write-Step "Adding a missing hosts entry and trusting the verified public certificate."
    Add-HostMappingIfMissing
    Import-VerifiedCertificate -Certificate $Certificate
}

Write-Step "Resolving $VmDnsName and confirming it maps to $VmIpText."
$ResolvedAddresses = @(
    [System.Net.Dns]::GetHostAddresses($VmDnsName) |
        Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
        } |
        ForEach-Object { $_.IPAddressToString }
)
if ($ResolvedAddresses -notcontains $VmIpText) {
    throw "$VmDnsName resolves to '$($ResolvedAddresses -join ', ')', not $VmIpText."
}

Write-Step "Testing TCP 5986."
$TcpReady = Test-NetConnection -ComputerName $VmDnsName -Port 5986 -InformationLevel Quiet
if (-not $TcpReady) {
    throw "TCP 5986 is not reachable at $VmDnsName ($VmIpText)."
}

$VmComputerName = [string]$Profile.host_name
if ([string]::IsNullOrWhiteSpace($VmComputerName)) {
    throw "vm-profile.json does not contain host_name."
}
if ($null -eq $Credential) {
    $Credential = Get-Credential -UserName "$VmComputerName\$RunnerUser"
}

Write-Step "Testing authenticated WinRM HTTPS."
$testWsManParams = @{
    ComputerName = $VmDnsName
    UseSSL = $true
    Authentication = "Negotiate"
    Credential = $Credential
    ErrorAction = "Stop"
}
Test-WSMan @testWsManParams | Out-Null

New-Item -ItemType Directory -Path $LocalProbeRoot -ErrorAction Stop | Out-Null
[System.IO.File]::WriteAllText(
    $LocalProbePath,
    "edreval-winrm-probe-$ProbeId",
    [System.Text.Encoding]::ASCII
)
$LocalHash = (Get-FileHash -LiteralPath $LocalProbePath -Algorithm SHA256).Hash

try {
    Write-Step "Opening the WinRM session and validating guest identity."
    $SessionOption = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
    $newSessionParams = @{
        ComputerName = $VmDnsName
        UseSSL = $true
        Authentication = "Negotiate"
        Credential = $Credential
        SessionOption = $SessionOption
    }
    $Session = New-PSSession @newSessionParams

    $GuestInfo = Invoke-Command -Session $Session -ScriptBlock {
        param($ExpectedLogsRoot)
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            host_name = $env:COMPUTERNAME
            os_caption = $os.Caption
            os_architecture = $os.OSArchitecture
            sample_logs_exists = Test-Path -LiteralPath $ExpectedLogsRoot -PathType Container
            process_identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    } -ArgumentList $RemoteLogsRoot

    if ($GuestInfo.host_name -ne $VmComputerName) {
        throw "Connected guest '$($GuestInfo.host_name)' does not match '$VmComputerName'."
    }
    if ($GuestInfo.os_caption -notmatch "Windows (10|11)") {
        throw "Connected guest is not Windows 10 or Windows 11: '$($GuestInfo.os_caption)'."
    }
    if ($GuestInfo.os_architecture -notmatch "64") {
        throw "Connected guest is not 64-bit: '$($GuestInfo.os_architecture)'."
    }
    if (-not $GuestInfo.sample_logs_exists) {
        throw "The SampleLogs directory is missing in the guest."
    }

    Write-Step "Uploading the probe as a .part file."
    Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    } -ArgumentList $RemoteProbeRoot
    Copy-Item -LiteralPath $LocalProbePath -Destination $RemotePartPath -ToSession $Session

    Write-Step "Verifying the guest SHA-256 and atomically renaming the probe."
    $RemotePartHash = Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } -ArgumentList $RemotePartPath
    if ($RemotePartHash -ne $LocalHash) {
        throw "Uploaded .part SHA-256 does not match the local probe."
    }

    Invoke-Command -Session $Session -ScriptBlock {
        param($PartPath, $FinalPath)
        Move-Item -LiteralPath $PartPath -Destination $FinalPath
    } -ArgumentList $RemotePartPath, $RemoteFinalPath
    $RemoteFinalHash = Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } -ArgumentList $RemoteFinalPath
    if ($RemoteFinalHash -ne $LocalHash) {
        throw "Final guest SHA-256 does not match the local probe."
    }

    Write-Step "Downloading the probe and verifying the round-trip SHA-256."
    Copy-Item -LiteralPath $RemoteFinalPath -Destination $RoundTripPath -FromSession $Session
    $RoundTripHash = (Get-FileHash -LiteralPath $RoundTripPath -Algorithm SHA256).Hash
    if ($RoundTripHash -ne $LocalHash) {
        throw "Round-trip SHA-256 does not match the local probe."
    }

    [pscustomobject]@{
        success = $true
        vm_dns_name = $VmDnsName
        vm_ip = $VmIpText
        tcp_5986 = $TcpReady
        winrm_https = $true
        guest_host_name = $GuestInfo.host_name
        guest_identity = $GuestInfo.process_identity
        local_sha256 = $LocalHash
        remote_part_sha256 = $RemotePartHash
        remote_final_sha256 = $RemoteFinalHash
        round_trip_sha256 = $RoundTripHash
        all_hashes_match = $true
        remote_probe_root = $RemoteProbeRoot
    } | ConvertTo-Json -Depth 4
}
finally {
    if ($null -ne $Session) {
        try {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Path)
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            } -ArgumentList $RemoteProbeRoot -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not remove remote probe directory '$RemoteProbeRoot': $_"
        }
        Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $LocalProbeRoot) {
        Remove-Item -LiteralPath $LocalProbeRoot -Recurse -Force
    }
}
