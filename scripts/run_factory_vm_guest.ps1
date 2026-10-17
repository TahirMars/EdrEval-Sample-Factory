#Requires -Version 5.1

<#
.SYNOPSIS
Fixed WinRM HTTPS guest driver used by VmwareVerificationBackend.

.DESCRIPTION
This is not an operator shell. It accepts one schema-checked request file and a
guest password on stdin, uploads exactly one artifact, verifies SHA-256, asks the
interactive desktop worker (Session > 0) to start it without arguments, records
the actual process result, collects related SampleLogs and Sysmon facts for the
harness process tree and lab path prefixes, writes one result JSON, and removes
only the unique remote run directory. It never starts the Harness from WinRM
Session 0.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$RequestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-SafeName {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw "Request contains an unsafe identifier."
    }
}

function Convert-SysmonXmlData {
    param($Xml)
    $data = [ordered]@{}
    if ($null -eq $Xml -or $null -eq $Xml.Event -or $null -eq $Xml.Event.EventData) {
        return $data
    }
    foreach ($item in @($Xml.Event.EventData.Data)) {
        $name = [string]$item.Name
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $data[$name] = [string]$item.'#text'
        }
    }
    return $data
}

function Convert-SysmonEvent {
    param([Parameter(Mandatory = $true)]$EventRecord)
    return [pscustomobject]@{
        event_id = [int]$EventRecord.event_id
        record_id = [long]$EventRecord.record_id
        timestamp_utc = [string]$EventRecord.timestamp_utc
        data = Convert-SysmonXmlData -Xml ([xml]$EventRecord.xml)
    }
}

function New-RelatedSysmonIdentity {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [string[]]$PathPrefixes,
        [string[]]$ImageSuffixes
    )
    $pids = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $images = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $prefixes = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $suffixes = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$pids.Add([string]$ProcessId)
    [void]$pids.Add(("0x{0:x}" -f $ProcessId))
    $artifact = $ArtifactPath.Trim().ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($artifact)) {
        [void]$images.Add($artifact)
    }
    foreach ($prefix in @($PathPrefixes)) {
        if ([string]::IsNullOrWhiteSpace($prefix)) {
            continue
        }
        $normalized = $prefix.Trim().Replace("/", "\").TrimEnd("\").ToLowerInvariant() + "\"
        [void]$prefixes.Add($normalized)
    }
    foreach ($suffix in @($ImageSuffixes)) {
        if ([string]::IsNullOrWhiteSpace($suffix)) {
            continue
        }
        $normalizedSuffix = $suffix.Trim().Replace("/", "\").ToLowerInvariant()
        [void]$suffixes.Add($normalizedSuffix)
    }
    return [pscustomobject]@{
        Pids = $pids
        Images = $images
        Prefixes = $prefixes
        ImageSuffixes = $suffixes
    }
}

function Test-RelatedSysmonData {
    param(
        [Parameter(Mandatory = $true)]$Data,
        [Parameter(Mandatory = $true)]$Identity
    )
    foreach ($property in $Data.GetEnumerator()) {
        $name = [string]$property.Key
        $value = [string]$property.Value
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }
        if ($name -match '(?i)ProcessId$') {
            if ($Identity.Pids.Contains($value)) {
                return $true
            }
            continue
        }
        $lower = $value.ToLowerInvariant()
        if ($name -match '(?i)^(Image|TargetImage)$') {
            foreach ($suffix in $Identity.ImageSuffixes) {
                if ($lower.EndsWith($suffix)) {
                    return $true
                }
            }
        }
        if ($Identity.Images.Contains($lower)) {
            return $true
        }
        foreach ($prefix in $Identity.Prefixes) {
            if ($lower.StartsWith($prefix)) {
                return $true
            }
            if (
                $name -match '(?i)^(CommandLine|TargetObject|TargetFilename)$' -and
                $lower.Contains($prefix.TrimEnd("\"))
            ) {
                return $true
            }
        }
        if ($name -match '(?i)CommandLine$') {
            foreach ($image in $Identity.Images) {
                if (-not [string]::IsNullOrWhiteSpace($image) -and $lower.Contains($image)) {
                    return $true
                }
            }
        }
    }
    return $false
}

function Add-RelatedSysmonProcess {
    param(
        [Parameter(Mandatory = $true)][int]$EventId,
        [Parameter(Mandatory = $true)]$Data,
        [Parameter(Mandatory = $true)]$Identity
    )
    if ($EventId -ne 1) {
        return
    }
    if ($Data.Contains("ProcessId")) {
        $processId = [string]$Data["ProcessId"]
        if (-not [string]::IsNullOrWhiteSpace($processId)) {
            [void]$Identity.Pids.Add($processId)
            $parsed = 0
            if ([int]::TryParse($processId, [ref]$parsed) -and $parsed -gt 0) {
                [void]$Identity.Pids.Add(("0x{0:x}" -f $parsed))
            }
        }
    }
    if ($Data.Contains("Image")) {
        $image = [string]$Data["Image"]
        if (-not [string]::IsNullOrWhiteSpace($image)) {
            [void]$Identity.Images.Add($image.ToLowerInvariant())
        }
    }
}

function Convert-ToWinEventFilterTime {
    param([Parameter(Mandatory = $true)][datetime]$UtcValue)
    # Get-WinEvent FilterHashtable StartTime/EndTime compare against local
    # TimeCreated using the clock face. A UTC DateTime on a +08:00 guest is
    # treated as 03:00 local instead of 11:00, so a short EndTime window
    # returns no events.
    return [DateTime]::SpecifyKind(
        $UtcValue.ToUniversalTime().ToLocalTime(),
        [DateTimeKind]::Unspecified
    )
}

function Format-WinRmOpenError {
    param($Record)
    if ($null -eq $Record) {
        return "New-PSSession returned no session and no error record."
    }
    $exception = $Record.Exception
    $message = [string]$exception.Message
    if ([string]::IsNullOrWhiteSpace($message) -and $null -ne $exception.InnerException) {
        $message = [string]$exception.InnerException.Message
    }
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = [string]$Record
    }
    $category = ""
    if ($null -ne $Record.CategoryInfo) {
        $category = [string]$Record.CategoryInfo.Category
    }
    return "WinRM HTTPS session was not established: $message [$category]"
}

function Copy-FileToGuest {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Destination,
        [int]$ChunkSize = 262144,
        [int]$RetryCount = 5
    )
    $fullLocal = [System.IO.Path]::GetFullPath($LiteralPath)
    if (-not [System.IO.File]::Exists($fullLocal)) {
        throw "Local artifact does not exist."
    }
    $remoteDir = Split-Path -Parent $Destination
    $uploadFailure = $null
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Dir)
                New-Item -ItemType Directory -Path $Dir -Force | Out-Null
                $probe = Join-Path $Dir (".write-probe-" + [guid]::NewGuid().ToString("N"))
                [System.IO.File]::WriteAllBytes($probe, [byte[]]@(0))
                Remove-Item -LiteralPath $probe -Force
            } -ArgumentList $remoteDir
            Invoke-Command -Session $Session -ScriptBlock {
                param($Path)
                if (Test-Path -LiteralPath $Path) {
                    Remove-Item -LiteralPath $Path -Force
                }
                New-Item -ItemType File -Path $Path -Force | Out-Null
            } -ArgumentList $Destination
            $stream = [System.IO.File]::OpenRead($fullLocal)
            try {
                $buffer = New-Object byte[] $ChunkSize
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($read -eq $buffer.Length) {
                        $chunk = $buffer
                    }
                    else {
                        $chunk = New-Object byte[] $read
                        [Array]::Copy($buffer, $chunk, $read)
                    }
                    Invoke-Command -Session $Session -ScriptBlock {
                        param($Path, $Bytes)
                        $file = [System.IO.File]::Open(
                            $Path,
                            [System.IO.FileMode]::Append,
                            [System.IO.FileAccess]::Write,
                            [System.IO.FileShare]::None
                        )
                        try {
                            $file.Write($Bytes, 0, $Bytes.Length)
                        }
                        finally {
                            $file.Dispose()
                        }
                    } -ArgumentList $Destination, $chunk
                }
            }
            finally {
                $stream.Dispose()
            }
            return
        }
        catch {
            $uploadFailure = $_
            Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 8))
        }
    }
    throw "Guest upload failed after $RetryCount attempts: $uploadFailure"
}

function Convert-ToByteArray {
    param($Value)
    if ($null -eq $Value) {
        return [byte[]]@()
    }
    if ($Value -is [byte[]]) {
        return $Value
    }
    if ($Value -is [byte]) {
        return [byte[]](, $Value)
    }
    return [byte[]]@($Value)
}

function Convert-ToWin32ExtendedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\')) {
        return $full
    }
    if ($full.StartsWith('\\')) {
        return '\\?\UNC\' + $full.Substring(2)
    }
    return '\\?\' + $full
}

function Copy-FileFromGuest {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$RemoteLiteralPath,
        [Parameter(Mandatory = $true)][string]$Destination,
        [int]$RetryCount = 5
    )
    $fullLocal = [System.IO.Path]::GetFullPath($Destination)
    $extendedLocal = Convert-ToWin32ExtendedPath -Path $fullLocal
    $extendedDir = Convert-ToWin32ExtendedPath -Path (Split-Path -Parent $fullLocal)
    [void][System.IO.Directory]::CreateDirectory($extendedDir)
    $downloadFailure = $null
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $raw = Invoke-Command -Session $Session -ScriptBlock {
                param($Path)
                if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                    throw "Remote file does not exist."
                }
                [System.IO.File]::ReadAllBytes($Path)
            } -ArgumentList $RemoteLiteralPath
            $bytes = Convert-ToByteArray -Value $raw
            if ([System.IO.File]::Exists($extendedLocal)) {
                [System.IO.File]::Delete($extendedLocal)
            }
            [System.IO.File]::WriteAllBytes($extendedLocal, $bytes)
            return
        }
        catch {
            $downloadFailure = $_
            Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 8))
        }
    }
    throw "Guest download failed after $RetryCount attempts: $downloadFailure"
}

function Wait-InteractiveWorker {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$RunnerUser,
        [Parameter(Mandatory = $true)][string]$HeartbeatPath,
        [Parameter(Mandatory = $true)][double]$TimeoutSeconds
    )
    $deadline = [datetime]::UtcNow.AddSeconds([Math]::Max($TimeoutSeconds, 15))
    $last = $null
    $workerTaskStarted = $false
    while ([datetime]::UtcNow -lt $deadline) {
        $last = Invoke-Command -Session $Session -ScriptBlock {
            param($User, $Path)
            $interactiveProcess = @(
                Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.SessionId -gt 0 }
            ) | Select-Object -First 1
            $heartbeatAge = $null
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                $text = [string](Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)
                $parsed = [datetime]::MinValue
                if (
                    -not [string]::IsNullOrWhiteSpace($text) -and
                    [datetime]::TryParse(
                        $text.Trim(),
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind,
                        [ref]$parsed
                    )
                ) {
                    $heartbeatAge = [Math]::Abs(([datetime]::UtcNow - $parsed.ToUniversalTime()).TotalSeconds)
                }
            }
            [pscustomobject]@{
                interactive = ($null -ne $interactiveProcess)
                session_id = if ($null -ne $interactiveProcess) { [int]$interactiveProcess.SessionId } else { $null }
                runner_user = $User
                heartbeat_age_s = $heartbeatAge
            }
        } -ArgumentList $RunnerUser, $HeartbeatPath
        if (
            $last.interactive -and
            $null -ne $last.heartbeat_age_s -and
            [double]$last.heartbeat_age_s -le 20
        ) {
            return $last
        }
        if (-not $workerTaskStarted -and $last.interactive) {
            Invoke-Command -Session $Session -ScriptBlock {
                $taskName = "EdrEvalInteractiveWorker"
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($null -eq $task) {
                    return
                }
                try {
                    if ($task.State -eq "Running") {
                        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    }
                    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                }
                catch {
                    return
                }
            }
            $workerTaskStarted = $true
        }
        Start-Sleep -Seconds 2
    }
    throw (
        "Interactive console session for $RunnerUser is not ready. " +
        "Need a logged-on desktop and EdrEvalInteractiveWorker heartbeat; " +
        "Session 0 WinRM cannot host UAC. " +
        "Last interactive=$($last.interactive) heartbeat_age_s=$($last.heartbeat_age_s). " +
        "If configure_factory_validation_vm.ps1 just re-registered the logon task, " +
        "log off/auto-logon once then recapture the snapshot."
    )
}

function Invoke-InteractiveLaunch {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )
    Invoke-Command -Session $Session -ScriptBlock {
        param($LaunchRequestPath, $Artifact, $TimeoutMs)
        $body = [ordered]@{
            schema_version = "factory-vmware-interactive-launch-v1"
            artifact_path = $Artifact
            timeout_ms = [int]$TimeoutMs
        }
        $body | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $LaunchRequestPath -Encoding UTF8
    } -ArgumentList $RequestPath, $ArtifactPath, $TimeoutMilliseconds

    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMilliseconds + 20000)
    $parsed = $null
    while ([datetime]::UtcNow -lt $deadline) {
        $raw = Invoke-Command -Session $Session -ScriptBlock {
            param($Path)
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                return $null
            }
            try {
                Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                # Worker may still be writing launch-result.json.
                $null
            }
        } -ArgumentList $ResultPath
        if (-not [string]::IsNullOrWhiteSpace([string]$raw)) {
            try {
                $candidate = $raw | ConvertFrom-Json
                if ($candidate.schema_version -eq "factory-vmware-interactive-launch-result-v1") {
                    $parsed = $candidate
                    break
                }
            }
            catch {
                # Partial JSON while the worker flushes the result file.
            }
        }
        Start-Sleep -Milliseconds 400
    }
    if ($null -eq $parsed) {
        throw "Interactive worker did not write launch-result.json before timeout."
    }
    if ([int]$parsed.session_id -le 0) {
        throw (
            "Harness was not launched in an interactive session " +
            "(session_id=$($parsed.session_id))."
        )
    }
    return $parsed
}

$RequestPath = (Resolve-Path -LiteralPath $RequestPath).Path
$Request = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Request.schema_version -ne "factory-vmware-guest-request-v1") {
    throw "Unsupported guest request schema."
}
foreach ($name in @($Request.recipe_id, $Request.guest_artifact_name)) {
    Require-SafeName -Value ([string]$name)
}
if ([string]$Request.artifact_sha256 -notmatch '^[a-f0-9]{64}$') {
    throw "Request artifact_sha256 is invalid."
}
$LocalArtifactPath = [System.IO.Path]::GetFullPath([string]$Request.local_artifact_path)
if (-not (Test-Path -LiteralPath $LocalArtifactPath -PathType Leaf)) {
    throw "Local artifact does not exist."
}
$LocalHash = (Get-FileHash -LiteralPath $LocalArtifactPath -Algorithm SHA256).Hash
if ($LocalHash.ToLowerInvariant() -ne [string]$Request.artifact_sha256) {
    throw "Local artifact SHA-256 does not match the request."
}

$Profile = Get-Content -LiteralPath $Request.vm_profile_path -Raw -Encoding UTF8 |
    ConvertFrom-Json
if ($Profile.schema_version -ne "edreval-factory-vm-bootstrap-v1") {
    throw "Unsupported VM profile schema."
}
if ($Profile.vm_dns_name -ne $Request.vm_dns_name) {
    throw "VM profile DNS identity does not match the request."
}
$Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [string]$Request.winrm_certificate_path
)
$ProfileThumbprint = ([string]$Profile.management.certificate.thumbprint).ToUpperInvariant()
if ($Certificate.Thumbprint.ToUpperInvariant() -ne $ProfileThumbprint) {
    throw "WinRM certificate does not match the VM profile."
}
if ([string]$Profile.management.runner_user -ne [string]$Request.runner_user) {
    throw "VM profile runner identity does not match the request."
}

$Password = [Console]::In.ReadToEnd()
if (
    [string]::IsNullOrEmpty($Password) -or
    $Password.Contains([char]13) -or
    $Password.Contains([char]10)
) {
    throw "Guest password stdin must be one exact non-empty line without a terminator."
}
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = [System.Management.Automation.PSCredential]::new(
    "$($Profile.host_name)\$($Request.runner_user)",
    $SecurePassword
)
$Password = $null
$SecurePassword = $null

$RunId = [guid]::NewGuid().ToString("N")
$RemoteRunRoot = Join-Path ([string]$Request.remote_runs_root) $RunId
$RemotePartPath = Join-Path $RemoteRunRoot "$($Request.guest_artifact_name).part"
$RemoteArtifactPath = Join-Path $RemoteRunRoot ([string]$Request.guest_artifact_name)
$LocalLogRoot = Join-Path ([string]$Request.evidence_dir) "sample-logs"
$ResultPath = [string]$Request.result_path
$Session = $null

try {
    [void][System.IO.Directory]::CreateDirectory(
        (Convert-ToWin32ExtendedPath -Path $LocalLogRoot)
    )
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($null -eq $winrmService -or $winrmService.Status -ne "Running") {
        throw (
            "Host WinRM service is not running. New-PSSession requires the local " +
            "WinRM client stack. Start it elevated with Start-Service WinRM " +
            "(do not run winrm quickconfig)."
        )
    }
    $sessionParams = @{
        ComputerName = [string]$Request.vm_dns_name
        UseSSL = $true
        Authentication = "Negotiate"
        Credential = $Credential
        SessionOption = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 120000
        ErrorAction = "Stop"
    }
    $WinRmOpenTimeoutS = 180
    if ($Request.PSObject.Properties.Name -contains "winrm_open_timeout_s") {
        $WinRmOpenTimeoutS = [double]$Request.winrm_open_timeout_s
    }
    if ($WinRmOpenTimeoutS -lt 15) {
        $WinRmOpenTimeoutS = 15
    }
    $deadline = [datetime]::UtcNow.AddSeconds($WinRmOpenTimeoutS)
    $openFailure = $null
    while ($null -eq $Session -and [datetime]::UtcNow -lt $deadline) {
        try {
            $Session = New-PSSession @sessionParams
            if ($null -eq $Session) {
                throw "New-PSSession returned a null session."
            }
        }
        catch {
            $openFailure = $_
            [Console]::Error.WriteLine((Format-WinRmOpenError -Record $_))
            Start-Sleep -Seconds 2
        }
    }
    if ($null -eq $Session) {
        if ($null -eq $openFailure -and $Error.Count -gt 0) {
            $openFailure = $Error[0]
        }
        throw (Format-WinRmOpenError -Record $openFailure)
    }

    $GuestIdentity = Invoke-Command -Session $Session -ScriptBlock {
        [pscustomobject]@{
            host_name = $env:COMPUTERNAME
            identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    }
    if ($GuestIdentity.host_name -ne $Profile.host_name) {
        throw "Connected guest host identity does not match the VM profile."
    }

    Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    } -ArgumentList $RemoteRunRoot

    Copy-FileToGuest -Session $Session -LiteralPath $LocalArtifactPath -Destination $RemotePartPath
    $RemotePartHash = Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } -ArgumentList $RemotePartPath
    if ($RemotePartHash.ToLowerInvariant() -ne [string]$Request.artifact_sha256) {
        throw "Remote .part SHA-256 does not match the request."
    }
    Invoke-Command -Session $Session -ScriptBlock {
        param($PartPath, $FinalPath)
        Move-Item -LiteralPath $PartPath -Destination $FinalPath
    } -ArgumentList $RemotePartPath, $RemoteArtifactPath
    $RemoteFinalHash = Invoke-Command -Session $Session -ScriptBlock {
        param($Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } -ArgumentList $RemoteArtifactPath
    if ($RemoteFinalHash.ToLowerInvariant() -ne [string]$Request.artifact_sha256) {
        throw "Remote final SHA-256 does not match the request."
    }

    $HeartbeatPath = Join-Path ([string]$Request.remote_logs_root) "interactive-worker.heartbeat"
    $InteractiveWaitS = $WinRmOpenTimeoutS
    if ($InteractiveWaitS -lt 30) {
        $InteractiveWaitS = 30
    }
    $null = Wait-InteractiveWorker `
        -Session $Session `
        -RunnerUser ([string]$Request.runner_user) `
        -HeartbeatPath $HeartbeatPath `
        -TimeoutSeconds $InteractiveWaitS

    $LaunchRequestPath = Join-Path $RemoteRunRoot "launch-request.json"
    $LaunchResultPath = Join-Path $RemoteRunRoot "launch-result.json"
    $Execution = Invoke-InteractiveLaunch `
        -Session $Session `
        -ArtifactPath $RemoteArtifactPath `
        -RequestPath $LaunchRequestPath `
        -ResultPath $LaunchResultPath `
        -TimeoutMilliseconds ([int]([double]$Request.execution_timeout_s * 1000))

    if ([double]$Request.settle_timeout_s -gt 0) {
        Start-Sleep -Milliseconds ([int]([double]$Request.settle_timeout_s * 1000))
    }

    $SampleLogPaths = @()
    if ([bool]$Request.execution_logging) {
        $RemoteLogs = @(
            Invoke-Command -Session $Session -ScriptBlock {
                param($Root, $RecipeId, $StartedAtUtc)
                $started = [DateTime]::Parse(
                    $StartedAtUtc,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).AddSeconds(-2)
                Get-ChildItem -LiteralPath $Root -Filter "$RecipeId-*.jsonl" -File |
                    Where-Object { $_.LastWriteTimeUtc -ge $started } |
                    Select-Object FullName, Name, LastWriteTimeUtc
            } -ArgumentList $Request.remote_logs_root, $Request.recipe_id, $Execution.started_at_utc
        )
        foreach ($remoteLog in $RemoteLogs) {
            Require-SafeName -Value ([string]$remoteLog.Name)
            $localLogPath = Join-Path $LocalLogRoot ([string]$remoteLog.Name)
            Copy-FileFromGuest -Session $Session -RemoteLiteralPath ([string]$remoteLog.FullName) -Destination $localLogPath
            $SampleLogPaths += "sample-logs/$($remoteLog.Name)"
        }
    }

    $SysmonEvents = @()
    if ([bool]$Profile.readiness.sensors_ready -and $Execution.process_created) {
        $PathPrefixes = [System.Collections.Generic.List[string]]::new()
        [void]$PathPrefixes.Add($RemoteRunRoot)
        if ($Request.PSObject.Properties.Name -contains "related_path_prefixes") {
            foreach ($item in @($Request.related_path_prefixes)) {
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    [void]$PathPrefixes.Add($text)
                }
            }
        }
        $ImageSuffixes = [System.Collections.Generic.List[string]]::new()
        if ($Request.PSObject.Properties.Name -contains "related_image_suffixes") {
            foreach ($item in @($Request.related_image_suffixes)) {
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    [void]$ImageSuffixes.Add($text)
                }
            }
        }
        $EventIdText = ""
        if ($Request.PSObject.Properties.Name -contains "sysmon_event_ids") {
            $EventIdText = @(
                @($Request.sysmon_event_ids) |
                    ForEach-Object { [string]$_ } |
                    Where-Object { $_.Trim() -match '^\d+$' }
            ) -join ","
        }
        $helperSource = @(
            "function Convert-SysmonXmlData { ${function:Convert-SysmonXmlData} }"
            "function Convert-ToWinEventFilterTime { ${function:Convert-ToWinEventFilterTime} }"
            "function New-RelatedSysmonIdentity { ${function:New-RelatedSysmonIdentity} }"
            "function Test-RelatedSysmonData { ${function:Test-RelatedSysmonData} }"
            "function Add-RelatedSysmonProcess { ${function:Add-RelatedSysmonProcess} }"
        ) -join "`n"
        $collected = @(
            Invoke-Command -Session $Session -ScriptBlock {
                param(
                    $HelperSource,
                    $LogName,
                    $StartedAtUtc,
                    $FinishedAtUtc,
                    $SettleTimeoutS,
                    $MaxEvents,
                    $EventIdText,
                    $ArtifactPath,
                    $ProcessId,
                    $PrefixText,
                    $SuffixText
                )
                . ([scriptblock]::Create([string]$HelperSource))
                $started = Convert-ToWinEventFilterTime -UtcValue (
                    [DateTime]::Parse(
                        $StartedAtUtc,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind
                    ).AddSeconds(-2)
                )
                $ended = Convert-ToWinEventFilterTime -UtcValue (
                    [DateTime]::Parse(
                        $FinishedAtUtc,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind
                    ).AddSeconds([Math]::Max([double]$SettleTimeoutS, 1.0) + 1.0)
                )
                $pathPrefixes = @(
                    [string]$PrefixText -split "\|" |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                )
                $imageSuffixes = @(
                    [string]$SuffixText -split "\|" |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                )
                $identity = New-RelatedSysmonIdentity `
                    -ProcessId ([int]$ProcessId) `
                    -ArtifactPath ([string]$ArtifactPath) `
                    -PathPrefixes $pathPrefixes `
                    -ImageSuffixes $imageSuffixes
                $filter = @{
                    LogName = $LogName
                    StartTime = $started
                    EndTime = $ended
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$EventIdText)) {
                    $filter.Id = @(
                        [string]$EventIdText -split "," |
                            ForEach-Object { [int]$_.Trim() }
                    )
                }
                Get-WinEvent -FilterHashtable $filter -Oldest -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $relatedRecord = $null
                        try {
                            $xml = [xml]$_.ToXml()
                            $data = Convert-SysmonXmlData -Xml $xml
                            if (Test-RelatedSysmonData -Data $data -Identity $identity) {
                                Add-RelatedSysmonProcess -EventId ([int]$_.Id) -Data $data -Identity $identity
                                $relatedRecord = [pscustomobject]@{
                                    event_id = [int]$_.Id
                                    record_id = [long]$_.RecordId
                                    timestamp_utc = $_.TimeCreated.ToUniversalTime().ToString("o")
                                    xml = $_.ToXml()
                                }
                            }
                        }
                        catch {
                            $relatedRecord = $null
                        }
                        if ($null -ne $relatedRecord) {
                            $relatedRecord
                        }
                    } |
                    Select-Object -First $MaxEvents
            } -ArgumentList @(
                $helperSource,
                $Request.sysmon_log_name,
                $Execution.started_at_utc,
                $Execution.finished_at_utc,
                $Request.settle_timeout_s,
                $Request.max_sysmon_events,
                $EventIdText,
                $RemoteArtifactPath,
                [int]$Execution.process_id,
                ($PathPrefixes.ToArray() -join "|"),
                ($ImageSuffixes.ToArray() -join "|")
            )
        )
        $identity = New-RelatedSysmonIdentity `
            -ProcessId ([int]$Execution.process_id) `
            -ArtifactPath $RemoteArtifactPath `
            -PathPrefixes @($PathPrefixes.ToArray()) `
            -ImageSuffixes @($ImageSuffixes.ToArray())
        foreach ($record in $collected) {
            $event = Convert-SysmonEvent -EventRecord $record
            if (-not (Test-RelatedSysmonData -Data $event.data -Identity $identity)) {
                continue
            }
            Add-RelatedSysmonProcess -EventId $event.event_id -Data $event.data -Identity $identity
            $data = @{}
            foreach ($property in $event.data.GetEnumerator()) {
                $data[[string]$property.Key] = [string]$property.Value
            }
            $SysmonEvents += [pscustomobject]@{
                event_id = $event.event_id
                record_id = $event.record_id
                timestamp_utc = $event.timestamp_utc
                data = $data
            }
        }
    }

    $Result = [ordered]@{
        schema_version = "factory-vmware-guest-result-v1"
        run_id = $RunId
        process_created = [bool]$Execution.process_created
        process_id = $Execution.process_id
        session_id = $Execution.session_id
        exit_code = $Execution.exit_code
        timed_out = [bool]$Execution.timed_out
        error = $Execution.error
        remote_artifact_path = $RemoteArtifactPath
        remote_artifact_sha256 = $RemoteFinalHash.ToLowerInvariant()
        started_at_utc = $Execution.started_at_utc
        finished_at_utc = $Execution.finished_at_utc
        sample_log_paths = @($SampleLogPaths)
        sysmon_events = @($SysmonEvents)
    }
    $Result | ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
finally {
    if ($null -ne $Session) {
        try {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Path)
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            } -ArgumentList $RemoteRunRoot -ErrorAction Stop
        }
        catch {
            Write-Warning "Remote run cleanup failed; snapshot rollback is still required."
        }
        Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }
}
