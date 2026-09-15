#Requires -Version 5.1
<#
.SYNOPSIS
    Capture Bambu Studio's startup cert-API request with TLS decryption.

.DESCRIPTION
    Sets SSLKEYLOGFILE, starts a dumpcap capture, launches Bambu Studio (which
    makes the get_app_cert request on every startup), then injects the TLS
    secrets into the capture with editcap so it is decryptable in Wireshark.

    While that runs, a second tshark watches the same interface and decrypts in
    real time using the key log as it fills, so the capture can be stopped as
    soon as the cert request is actually seen instead of waiting out -Seconds.

    All output lands in the current directory:
        <base>-keys.log               the TLS key log
        <base>.pcapng                 the raw capture
        <base>-decrypted.pcapng       the capture with secrets embedded
        <base>-trigger-url.txt        the URL of the request that matched
                                      the trigger
        <base>-trigger-response.json  the body of the response to the request
                                      that matched the trigger

    The response JSON feeds straight into decrypt.py.

.EXAMPLE
    .\Capture-BambuCert.ps1
    .\Capture-BambuCert.ps1 -Seconds 90 -CloseStudio
    .\Capture-BambuCert.ps1 -TriggerFilter 'http.request.uri contains "app_cert"'
    .\Capture-BambuCert.ps1 -TriggerFilter ''      # no live monitor, just wait
    .\Capture-BambuCert.ps1 -ListInterfaces
#>
[CmdletBinding()]
param(
    # Path to bambu-studio.exe.  Auto-detected from the usual install locations.
    [string] $StudioPath,

    # dumpcap interface (name or index).  Auto-detected from the default route.
    [string] $Interface,

    # How long to capture.  Press any key to stop early.
    [int]    $Seconds = 60,

    # BPF capture filter.  Empty string captures everything.
    [string] $CaptureFilter = 'tcp port 443',

    # Wireshark display filter evaluated live against the decrypted stream.
    # The capture stops once a packet matches.  Empty string = no monitor.
    # Matches the applications request under either HTTP/1.1 or HTTP/2.
    [string] $TriggerFilter = '(http.host == "api.bambulab.com" and http.request.uri contains "/v1/iot-service/api/user/applications/") or (http2.headers.authority == "api.bambulab.com" and http2.headers.path contains "/v1/iot-service/api/user/applications/")',

    # Keep capturing this long after the trigger matches, so the rest of the
    # exchange (the response, if the request is what matched) lands in the pcap.
    [int]    $TriggerGraceSeconds = 5,

    # Wireshark install directory.
    [string] $WiresharkDir = 'C:\Program Files\Wireshark',

    # Base name for the output files.  Defaults to bambu-<timestamp>.
    [string] $BaseName,

    # Close Bambu Studio when the capture finishes.  A trigger match always
    # closes it, switch or not.
    [switch] $CloseStudio,

    # Print the available capture interfaces and exit.
    [switch] $ListInterfaces
)

$ErrorActionPreference = 'Stop'

function Find-Tool {
    param([string] $Name)
    $p = Join-Path $WiresharkDir $Name
    if (Test-Path -LiteralPath $p) { return $p }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Rebuild the request URL from the monitor's output fields:
#   frame.number|http.host|http.request.uri|http2.headers.authority|http2.headers.path
function ConvertTo-TriggerUrl {
    param([string] $Line)
    $f = $Line -split '\|'
    $auth = if ($f.Count -ge 2 -and $f[1]) { $f[1] } elseif ($f.Count -ge 4) { $f[3] } else { '' }
    $path = if ($f.Count -ge 3 -and $f[2]) { $f[2] } elseif ($f.Count -ge 5) { $f[4] } else { '' }
    if ($auth -or $path) { "https://$auth$path" } else { $Line }
}

# Start-Process joins -ArgumentList without quoting, so quote here.
function Format-CmdArg {
    param([string] $Value)
    if ($Value -match '[\s"]') { '"' + ($Value -replace '"', '\"') + '"' } else { $Value }
}

$dumpcap = Find-Tool 'dumpcap.exe'
$editcap = Find-Tool 'editcap.exe'
$tshark  = Find-Tool 'tshark.exe'
if (-not $dumpcap) { throw "dumpcap.exe not found. Install Wireshark (with Npcap), or pass -WiresharkDir." }
if (-not $editcap) { throw "editcap.exe not found in $WiresharkDir." }
if ($TriggerFilter -and -not $tshark) {
    Write-Warning "tshark.exe not found in $WiresharkDir -- live monitoring disabled, falling back to the -Seconds timer."
    $TriggerFilter = ''
}

if ($ListInterfaces) { & $dumpcap -D; return }

# --- resolve Bambu Studio ---------------------------------------------------
if (-not $StudioPath) {
    $candidates = @(
        'C:\Program Files\Bambu Studio\bambu-studio.exe'
        'C:\Program Files\Bambu Studio\BambuStudio.exe'
        'C:\Program Files (x86)\Bambu Studio\bambu-studio.exe'
        "$env:LOCALAPPDATA\Programs\Bambu Studio\bambu-studio.exe"
    )
    $StudioPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $StudioPath -or -not (Test-Path -LiteralPath $StudioPath)) {
    throw "Bambu Studio not found. Pass -StudioPath 'C:\path\to\bambu-studio.exe'."
}

# A running instance will hand the launch off to the existing process, which was
# started without SSLKEYLOGFILE -- so no keys, and no fresh startup request.
$running = Get-Process -Name 'bambu-studio', 'BambuStudio' -ErrorAction SilentlyContinue
if ($running) {
    $pids = ($running.Id -join ', ')
    throw "Bambu Studio is already running (PID $pids). Close it first -- a second launch reuses the existing process, which has no key log."
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Not running as Administrator. Capture may fail unless Npcap was installed with its driver accessible to non-admins."
}

# --- output paths (absolute, in the current directory) ----------------------
$cwd = (Get-Location).ProviderPath
if (-not $BaseName) { $BaseName = 'bambu-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
$keylog    = Join-Path $cwd "$BaseName-keys.log"
$rawPcap   = Join-Path $cwd "$BaseName.pcapng"
$decPcap   = Join-Path $cwd "$BaseName-decrypted.pcapng"
$trigUrl   = Join-Path $cwd "$BaseName-trigger-url.txt"
$trigJson  = Join-Path $cwd "$BaseName-trigger-response.json"

# Must exist and be writable before the first TLS handshake.
New-Item -ItemType File -Path $keylog -Force | Out-Null
$env:SSLKEYLOGFILE = $keylog
Write-Host "SSLKEYLOGFILE = $keylog"

# --- pick an interface ------------------------------------------------------
if (-not $Interface) {
    try {
        $idx = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
        $guid = (Get-NetAdapter -InterfaceIndex $idx -ErrorAction Stop).InterfaceGuid
        $line = (& $dumpcap -D) | Where-Object { $_ -like "*$guid*" } | Select-Object -First 1
        if ($line -match '^\s*\d+\.\s+(\S+)') { $Interface = $Matches[1] }
    } catch { }
}
if (-not $Interface) {
    Write-Warning "Could not auto-detect the interface; falling back to 1. Use -ListInterfaces to choose."
    $Interface = '1'
}
Write-Host "Interface     = $Interface"

# --- start the capture ------------------------------------------------------
$dumpArgs = @('-i', $Interface, '-w', $rawPcap, '-a', "duration:$Seconds")
if ($CaptureFilter) { $dumpArgs += @('-f', $CaptureFilter) }

Write-Host "Starting capture..."
$dumpOut = Join-Path ([IO.Path]::GetTempPath()) ("dumpcap-out-" + [Guid]::NewGuid().ToString('N') + '.txt')
$dumpErr = Join-Path ([IO.Path]::GetTempPath()) ("dumpcap-err-" + [Guid]::NewGuid().ToString('N') + '.txt')
$dumpLine = ($dumpArgs | ForEach-Object { Format-CmdArg $_ }) -join ' '
$dump = Start-Process -FilePath $dumpcap -ArgumentList $dumpLine -PassThru -NoNewWindow `
                      -RedirectStandardOutput $dumpOut -RedirectStandardError $dumpErr

# Do not launch Studio until the capture file actually exists, or the startup
# request can slip through before dumpcap is listening.
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    if ($dump.HasExited) { break }
    if ((Test-Path -LiteralPath $rawPcap) -and (Get-Item -LiteralPath $rawPcap).Length -gt 0) { $ready = $true; break }
    Start-Sleep -Milliseconds 250
}
if ($dump.HasExited) {
    $msg = (Get-Content -LiteralPath $dumpErr -Raw -ErrorAction SilentlyContinue)
    Remove-Item -LiteralPath $dumpOut, $dumpErr -Force -ErrorAction SilentlyContinue
    throw "dumpcap exited immediately (exit code $($dump.ExitCode)).`n$msg"
}
if (-not $ready) { Write-Warning "Capture file did not appear; continuing anyway." }
Start-Sleep -Milliseconds 500

# --- live monitor -----------------------------------------------------------
# dumpcap has no content-based autostop, so a second, independent tshark reads
# the same interface and dissects as packets arrive.  It re-reads the key log
# whenever it meets a session it cannot decrypt yet, so secrets Bambu Studio
# appends after tshark started still take effect.  This process only decides
# *when to stop*; the raw dumpcap file plus the editcap pass below stay the
# authoritative copy.
$mon = $null
$monOut = $null
$monErr = $null
if ($TriggerFilter) {
    $monOut = Join-Path ([IO.Path]::GetTempPath()) ("tshark-mon-out-" + [Guid]::NewGuid().ToString('N') + '.txt')
    $monErr = Join-Path ([IO.Path]::GetTempPath()) ("tshark-mon-err-" + [Guid]::NewGuid().ToString('N') + '.txt')
    $monArgs = @(
        '-i', $Interface
        '-l'                                  # flush after every packet
        '-n'                                  # no name resolution
        '-Q'                                  # no "Capturing on ..." banner
        '-o', "tls.keylog_file:$keylog"
        '-Y', $TriggerFilter
        '-T', 'fields'
        '-E', 'separator=|'
        '-e', 'frame.number'
        '-e', 'http.host'
        '-e', 'http.request.uri'
        '-e', 'http2.headers.authority'
        '-e', 'http2.headers.path'
    )
    if ($CaptureFilter) { $monArgs += @('-f', $CaptureFilter) }
    $monLine = ($monArgs | ForEach-Object { Format-CmdArg $_ }) -join ' '
    $mon = Start-Process -FilePath $tshark -ArgumentList $monLine -PassThru -NoNewWindow `
                         -RedirectStandardOutput $monOut -RedirectStandardError $monErr
    Start-Sleep -Milliseconds 1500            # let it get on the wire
    if ($mon.HasExited) {
        Write-Warning "Live monitor exited immediately:`n$(Get-Content -LiteralPath $monErr -Raw -ErrorAction SilentlyContinue)"
        $mon = $null
    } else {
        Write-Host "Monitor       = $TriggerFilter"
    }
}

# --- launch Bambu Studio ----------------------------------------------------
# Start-Process inherits this process's environment, so the child and the
# in-process network plugin both see SSLKEYLOGFILE.
Write-Host "Launching $StudioPath"
$studio = Start-Process -FilePath $StudioPath -PassThru

$triggered   = $false
$triggerInfo = $null
$monReader   = $null

try {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline -and -not $dump.HasExited) {
        try {
            if ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null; break }
        } catch { }

        # Tail the monitor's output.  Opened ReadWrite so tshark keeps writing.
        if ($mon -and -not $monReader -and (Test-Path -LiteralPath $monOut)) {
            $monStream = [IO.File]::Open($monOut, [IO.FileMode]::Open,
                                         [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $monReader = New-Object IO.StreamReader($monStream)
        }
        if ($monReader) {
            while ($null -ne ($line = $monReader.ReadLine())) {
                if ($line.Trim()) { $triggered = $true; $triggerInfo = $line.Trim(); break }
            }
        }
        if ($triggered) {
            $triggerUrl = ConvertTo-TriggerUrl $triggerInfo
            Write-Host ''
            Write-Host "Trigger matched: $triggerUrl"
            try   { [IO.File]::WriteAllText($trigUrl, $triggerUrl + "`r`n") }
            catch { Write-Warning "Cannot write ${trigUrl}: $_" }
            if ($TriggerGraceSeconds -gt 0) {
                Write-Host "Draining for $TriggerGraceSeconds s..."
                Start-Sleep -Seconds $TriggerGraceSeconds
            }
            break
        }

        $left = [int]($deadline - (Get-Date)).TotalSeconds
        $keys = 0
        if (Test-Path -LiteralPath $keylog) {
            $keys = @(Get-Content -LiteralPath $keylog -ErrorAction SilentlyContinue).Count
        }
        $what = if ($mon) { 'watching' } else { 'capturing' }
        Write-Host -NoNewline ("`r  {0}... {1,3}s left, {2} key log lines   " -f $what, $left, $keys)
        Start-Sleep -Milliseconds 500
    }
    Write-Host ''
}
finally {
    if ($monReader) { $monReader.Dispose() }
    if ($mon -and -not $mon.HasExited) { Stop-Process -Id $mon.Id -Force -ErrorAction SilentlyContinue }
    if ($mon) { $mon.WaitForExit(5000) | Out-Null }
    if (-not $dump.HasExited) {
        Write-Host "Stopping capture..."
        Stop-Process -Id $dump.Id -Force -ErrorAction SilentlyContinue
    }
    $dump.WaitForExit(10000) | Out-Null
    Remove-Item -LiteralPath $dumpOut, $dumpErr -Force -ErrorAction SilentlyContinue
    if ($monOut) { Remove-Item -LiteralPath $monOut, $monErr -Force -ErrorAction SilentlyContinue }
}

if ($TriggerFilter -and -not $triggered) {
    Write-Warning "The trigger never matched -- the capture ran to the end of its window."
}

if (($CloseStudio -or $triggered) -and $studio) {
    Write-Host "Closing Bambu Studio..."
    if (-not $studio.HasExited) {
        $studio.CloseMainWindow() | Out-Null
        Start-Sleep -Seconds 3
        if (-not $studio.HasExited) { Stop-Process -Id $studio.Id -Force -ErrorAction SilentlyContinue }
    }
    # The launcher can hand off to another process, so sweep up by name too --
    # the script refused to start with any of these already running.
    Get-Process -Name 'bambu-studio', 'BambuStudio' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# --- inject the secrets -----------------------------------------------------
$keyLines = @(Get-Content -LiteralPath $keylog -ErrorAction SilentlyContinue |
              Where-Object { $_ -match '^[A-Z_]+ ' }).Count
if ($keyLines -eq 0) {
    Write-Warning "The key log is empty -- Bambu Studio did not honour SSLKEYLOGFILE this run."
    Write-Warning "The raw capture is still at $rawPcap but its TLS cannot be decrypted."
    return
}
Write-Host "Key log: $keyLines secrets"

# Native stderr becomes a *terminating* error while ErrorActionPreference is
# 'Stop', so a mere warning (a capture cut short mid-packet, say) would kill the
# script.  Judge these tools by their exit codes instead.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $editcap --inject-secrets "tls,$keylog" $rawPcap $decPcap 2>&1 |
        ForEach-Object { Write-Host "  editcap: $_" }
}
finally { $ErrorActionPreference = $prevEap }
if ($LASTEXITCODE -ne 0) { throw "editcap failed with exit code $LASTEXITCODE" }
Write-Host "Wrote $decPcap"

# --- tshark helpers ---------------------------------------------------------
# Not "& $tshark @Arguments": PowerShell 5.1 wraps an argument containing
# spaces in quotes but leaves the double quotes inside it unescaped, so every
# display filter below reaches tshark in pieces and dies as a syntax error.
# Build the command line by hand, the way the live monitor already does.
function Invoke-Tshark {
    param([string[]] $Arguments)
    $line = ($Arguments | ForEach-Object { Format-CmdArg $_ }) -join ' '
    $o = Join-Path ([IO.Path]::GetTempPath()) ("tshark-out-" + [Guid]::NewGuid().ToString('N') + '.txt')
    $e = Join-Path ([IO.Path]::GetTempPath()) ("tshark-err-" + [Guid]::NewGuid().ToString('N') + '.txt')
    try {
        $p = Start-Process -FilePath $tshark -ArgumentList $line -PassThru -NoNewWindow -Wait `
                           -RedirectStandardOutput $o -RedirectStandardError $e
        if ($p.ExitCode -ne 0) {
            $msg = @(Get-Content -LiteralPath $e -ErrorAction SilentlyContinue) -join ' '
            Write-Warning "tshark exited $($p.ExitCode): $msg"
        }
        ,@(Get-Content -LiteralPath $o -ErrorAction SilentlyContinue)
    }
    finally { Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue }
}

# tshark prints FT_BYTES fields as hex, with or without separators.
function ConvertFrom-TsharkHex {
    param([string] $Line)
    $hex = ($Line -replace '[^0-9a-fA-F]', '')
    if ($hex.Length -lt 2 -or ($hex.Length % 2) -ne 0) { return $null }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    ,$bytes
}

$bodyFields = @('http.file_data', 'http2.body.reassembled.data', 'http2.data.data')

# HTTP/1.1 requests carry http.response_in, which names the answering frame
# outright.  HTTP/2 has no such field, so fall back to the body-carrying
# packets of the same TCP (and HTTP/2) stream.
function Get-ResponseBody {
    param([string] $ResponseFrame, [string] $TcpStream, [string] $Http2Stream)
    foreach ($field in $bodyFields) {
        $filter = if ($ResponseFrame)              { "frame.number == $ResponseFrame" }
                  elseif ($TcpStream -and $Http2Stream) { "tcp.stream eq $TcpStream and http2.streamid eq $Http2Stream and $field" }
                  elseif ($TcpStream)              { "tcp.stream eq $TcpStream and $field" }
                  else                             { $null }
        if (-not $filter) { break }
        $lines = @(Invoke-Tshark @('-r', $decPcap, '-Y', $filter,
                                   '-T', 'fields', '-e', $field, '-E', 'occurrence=f'))
        foreach ($line in $lines) {
            if (-not $line) { continue }
            $bytes = ConvertFrom-TsharkHex $line
            if ($bytes) { return ,$bytes }
        }
    }
    return $null
}

# --- the exchange that matched the trigger ----------------------------------
# The live monitor is a separate capture, so its frame numbers mean nothing
# here; re-run the trigger filter over the decrypted file to locate the request
# and, through http.response_in, the response that answered it.
if ($tshark -and $TriggerFilter) {
    $row = @(Invoke-Tshark @('-r', $decPcap, '-Y', $TriggerFilter,
                             '-T', 'fields', '-E', 'separator=|', '-E', 'occurrence=f',
                             '-e', 'http.response_in', '-e', 'tcp.stream',
                             '-e', 'http2.streamid')) |
           Where-Object { $_ -and $_.Trim() } | Select-Object -First 1

    if (-not $row) {
        Write-Warning "The trigger matched live, but no packet in $decPcap matches the filter -- the request may not have decrypted in the offline pass."
    } else {
        $f      = $row -split '\|'
        $respIn = $f[0]
        $stream = $f[1]
        $h2sid  = $f[2]

        $body = Get-ResponseBody $respIn $stream $h2sid
        if ($body) {
            [IO.File]::WriteAllBytes($trigJson, $body)
            Write-Host ("Wrote $trigJson ({0:N0} bytes)" -f $body.Length)
        } else {
            Write-Warning "No response body found for the triggered request."
        }
    }
}

Write-Host ''
Write-Host "Files written to $cwd :"
Get-ChildItem -LiteralPath $cwd -Filter "$BaseName*" | ForEach-Object {
    Write-Host ("  {0,-40} {1,10:N0} bytes" -f $_.Name, $_.Length)
}
