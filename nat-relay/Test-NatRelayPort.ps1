[CmdletBinding(DefaultParameterSetName = 'Initial')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$')]
    [string]$HostName,

    [Parameter(Mandatory)]
    [ValidateCount(1, 20)]
    [ValidateRange(1, 65535)]
    [int[]]$PublicPorts,

    [Parameter(Mandatory, ParameterSetName = 'Initial')]
    [ValidatePattern('^[a-f0-9]{32}$')]
    [string]$Challenge,

    [Parameter(Mandatory, ParameterSetName = 'Switch')]
    [ValidatePattern('^/[A-Za-z0-9_-]{1,128}$')]
    [string]$WebSocketPath,

    [ValidatePattern('^sha256//[A-Za-z0-9+/]{43}=$')]
    [string]$TlsPin
)

$curl = (Get-Command curl.exe -ErrorAction Stop).Source
$tlsArgs = @()
if ($TlsPin) {
    # An exact SPKI pin still authenticates the temporary TLS endpoint.
    $tlsArgs = @('--insecure', '--pinnedpubkey', $TlsPin)
}
$verified = @()
foreach ($port in ($PublicPorts | Select-Object -Unique)) {
    if ($WebSocketPath) {
        $nonce = New-Object byte[] 16
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }
        $wsKey = [Convert]::ToBase64String($nonce)
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes($wsKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
            $accept = [Convert]::ToBase64String($sha1.ComputeHash($bytes))
        } finally { $sha1.Dispose() }
        $url = "https://${HostName}:${port}${WebSocketPath}"
        $reply = & $curl @tlsArgs --noproxy '*' --http1.1 --silent --connect-timeout 3 --max-time 4 --dump-header - --output NUL --header 'Connection: Upgrade' --header 'Upgrade: websocket' --header 'Sec-WebSocket-Version: 13' --header "Sec-WebSocket-Key: $wsKey" $url
    } else {
        $url = "https://${HostName}:${port}/nat-relay/${Challenge}/probe/${port}"
        $reply = & $curl @tlsArgs --noproxy '*' --silent --connect-timeout 3 --max-time 5 --max-filesize 256 --fail $url
    }
    $code = $LASTEXITCODE
    if ($WebSocketPath) {
        $headers = $reply -join "`n"
        if ($headers -match '(?m)^HTTP/1\.1 101\b' -and
            $headers -match "(?im)^Sec-WebSocket-Accept:\s*$([regex]::Escape($accept))\s*$") {
            $verified += $port
            Write-Host "${HostName}:${port} - Verified"
            continue
        }
        if ($headers -match '(?m)^HTTP/1\.1 ') {
            Write-Host "${HostName}:${port} - HTTPS replied without a matching WebSocket handshake"
            continue
        }
    }
    $status = switch ($code) {
        0 {
            if (($reply -join "`n").Trim() -ceq "nat-relay:${Challenge}:${port}") {
                $verified += $port
                'Verified'
            } else {
                'HTTPS replied but did not reach this VPS probe'
            }
        }
        7 { 'TCP connection failed' }
        28 { 'Connection timed out' }
        { $_ -in 35, 51, 60 } { 'TLS handshake or certificate failed' }
        90 { 'TLS public key did not match this VPS' }
        default { "Probe did not match this VPS (curl $code)" }
    }
    Write-Host "${HostName}:${port} - $status"
}

if ($verified.Count -eq 0) {
    Write-Host 'Verified public ports: none. Check the temporary TCP mappings and the domain DNS.'
    return
}
Write-Host ('Verified public ports: ' + ($verified -join ', '))
if ($WebSocketPath) {
    Write-Host 'Copy one Verified port to the waiting VPS terminal. Keep the old mapping until the new node is tested.'
    return
}
Write-Host 'Keep the selected public TCP mapping to the VPS probe port. Remove any temporary mappings you do not need.'
$choice = Read-Host 'Enter a verified public port to continue, or press Enter to cancel'
if (-not $choice) { return }
$port = 0
if (-not [int]::TryParse($choice, [ref]$port) -or $port -notin $verified) {
    throw 'Select one of the verified public ports.'
}
$url = "https://${HostName}:${port}/nat-relay/${Challenge}/select/${port}"
$reply = & $curl @tlsArgs --noproxy '*' --silent --connect-timeout 3 --max-time 5 --max-filesize 256 --fail --request POST $url
if ($LASTEXITCODE -ne 0 -or ($reply -join "`n").Trim() -cne "selected:${port}") {
    throw 'The VPS did not confirm the port. Check its probe terminal before retrying.'
}
Write-Host "Port $port confirmed. Return to the VPS terminal for the installation result and node link."
