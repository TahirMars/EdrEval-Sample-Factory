#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Destructively verifies a VMware Workstation baseline snapshot for factory use.

.DESCRIPTION
Run this script on the VMware host only after the guest bootstrap and WinRM
connection tests pass. It performs two independent cycles. Each cycle reverts
and starts the VM, writes a unique marker through WinRM, reverts again, starts
again, and proves the marker disappeared. The VM is left reverted to the named
snapshot. On success, only the local vm-profile.json proof fields are updated.

vmrun requires the encrypted-VM password in its argv. The script never prints
or persists that password, but local privileged process inspection may observe
it while vmrun is running.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$VmrunPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$VmxPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$SnapshotName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ProfilePath,

    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(30, 1800)]
    [int]$StartupTimeoutSeconds = 180,
    [ValidateRange(1, 30)]
    [int]$PollIntervalSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$VmrunPath = (Resolve-Path -LiteralPath $VmrunPath).Path
$VmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
$ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
$Profile = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Profile.schema_version -ne "edreval-factory-vm-bootstrap-v1") {
    throw "Unsupported VM profile schema."
}
if ($Profile.network.declared_mode -eq "nat" -and [bool]$Profile.network.isolated) {
    throw "VM profile cannot claim NAT is isolated."
}
$VmDnsName = [string]$Profile.vm_dns_name
$VmHostName = [string]$Profile.host_name
$RunnerUser = [string]$Profile.management.runner_user
$WinRmPort = [int]$Profile.management.winrm_https_port
$RunsRoot = [string]$Profile.directories.runs
if ($WinRmPort -ne 5986) {
    throw "VM profile WinRM HTTPS port must be 5986."
}
if ($null -eq $Credential) {
    $Credential = Get-Credential -UserName "$VmHostName\$RunnerUser"
}

$SecureVmPassword = Read-Host "Enter the VMware encrypted-VM password" -AsSecureString
$PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureVmPassword)
$VmPassword = $null
$CleanupRequired = $false

function Invoke-Vmrun {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command,
        [switch]$AllowNotPoweredOn
    )
    $arguments = @("-T", "ws", "-vp", $script:VmPassword) + $Command
    $output = & $VmrunPath @arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        return $output
    }
    if (
        $AllowNotPoweredOn -and
        $output -match "(?i)not powered on|未启动|未打开电源"
    ) {
        return $output
    }
    $safeOutput = $output.Replace($script:VmPassword, "[REDACTED]").Trim()
    throw "vmrun $($Command[0]) failed: $safeOutput"
}

function Wait-WinRm {
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $tcpParams = @{
            ComputerName = $VmDnsName
            Port = $WinRmPort
            InformationLevel = "Quiet"
            WarningAction = "SilentlyContinue"
        }
        if (Test-NetConnection @tcpParams) {
            $testParams = @{
                ComputerName = $VmDnsName
                UseSSL = $true
                Authentication = "Negotiate"
                Credential = $Credential
                ErrorAction = "SilentlyContinue"
            }
            if ($null -ne (Test-WSMan @testParams)) {
                return
            }
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }
    throw "WinRM HTTPS did not become ready within $StartupTimeoutSeconds seconds."
}

function Stop-And-Revert {
    Invoke-Vmrun -Command @("stop", $VmxPath, "hard") -AllowNotPoweredOn | Out-Null
    Invoke-Vmrun -Command @("revertToSnapshot", $VmxPath, $SnapshotName) | Out-Null
}

function Start-And-Wait {
    Invoke-Vmrun -Command @("start", $VmxPath, "nogui") | Out-Null
    Wait-WinRm
}

try {
    $VmPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PasswordPointer)
    if ([string]::IsNullOrEmpty($VmPassword)) {
        throw "VMware encrypted-VM password is empty."
    }
    $snapshots = Invoke-Vmrun -Command @("listSnapshots", $VmxPath, "showTree")
    $snapshotLines = @(
        $snapshots -split "\r?\n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -notmatch "(?i)^Total snapshots:" }
    )
    if ($snapshotLines -notcontains $SnapshotName) {
        throw "Snapshot '$SnapshotName' was not found."
    }
    if (-not $PSCmdlet.ShouldProcess($VmxPath, "Verify snapshot '$SnapshotName' twice")) {
        return
    }

    $CleanupRequired = $true
    foreach ($cycle in 1..2) {
        Write-Host "[EdrEval Snapshot Test] Cycle $($cycle): revert, start, and write marker."
        Stop-And-Revert
        Start-And-Wait
        $MarkerId = [guid]::NewGuid().ToString("N")
        $MarkerPath = Join-Path $RunsRoot "snapshot-proof-$MarkerId.txt"
        Invoke-Command -ComputerName $VmDnsName -UseSSL -Authentication Negotiate -Credential $Credential -ScriptBlock {
            param($Path, $Value)
            [System.IO.File]::WriteAllText($Path, $Value, [System.Text.Encoding]::ASCII)
        } -ArgumentList $MarkerPath, $MarkerId

        Write-Host "[EdrEval Snapshot Test] Cycle $($cycle): revert and prove marker removal."
        Stop-And-Revert
        Start-And-Wait
        $markerExists = Invoke-Command -ComputerName $VmDnsName -UseSSL -Authentication Negotiate -Credential $Credential -ScriptBlock {
            param($Path)
            Test-Path -LiteralPath $Path
        } -ArgumentList $MarkerPath
        if ($markerExists) {
            throw "Snapshot rollback did not remove marker '$MarkerPath'."
        }
    }

    Stop-And-Revert
    $CleanupRequired = $false
    $Profile.readiness | Add-Member -NotePropertyName snapshot_name -NotePropertyValue $SnapshotName -Force
    $Profile.readiness.snapshot_rollback_verified = $true
    $Profile.readiness.rollback_capable = $true
    $Profile.readiness | Add-Member -NotePropertyName snapshot_verified_at_utc -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) -Force
    $Profile | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $ProfilePath -Encoding UTF8
    Write-Host "[EdrEval Snapshot Test] PASS: two rollback cycles removed their markers."
    Write-Host "[EdrEval Snapshot Test] VM is left reverted to '$SnapshotName'."
}
finally {
    if ($CleanupRequired -and -not [string]::IsNullOrEmpty($VmPassword)) {
        try {
            Stop-And-Revert
        }
        catch {
            Write-Warning "Final snapshot restore failed; treat the VM as dirty."
        }
    }
    $VmPassword = $null
    $SecureVmPassword = $null
    if ($PasswordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    }
}
