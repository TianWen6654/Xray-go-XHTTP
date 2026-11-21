[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$HostName,

    [int[]]$PublicPorts
)

if (-not $PSBoundParameters.ContainsKey('PublicPorts')) {
    $inputPorts = Read-Host 'Enter all public TCP ports assigned to this VPS, separated by commas'
    $PublicPorts = @(
        foreach ($item in ($inputPorts.Trim() -split '[,，\s]+')) {
            $port = 0
            if (-not [int]::TryParse($item, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                throw "Invalid public TCP port: $item"
            }
            $port
        }
    )
}
if ($PublicPorts.Count -eq 0 -or @($PublicPorts | Where-Object { $_ -lt 1 -or $_ -gt 65535 }).Count -gt 0) {
    throw 'Public TCP ports must be between 1 and 65535.'
}

$ports = @($PublicPorts | Sort-Object -Unique)
$addresses = @([Net.Dns]::GetHostAddresses($HostName) | Where-Object {
    $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
})
if ($addresses.Count -eq 0) {
    throw "No IPv4 address found for $HostName."
}
$open = [Collections.Generic.HashSet[int]]::new()
$batchSize = 12
foreach ($address in $addresses) {
    Write-Host "Testing TCP to $HostName ($address)."
    for ($offset = 0; $offset -lt $ports.Count; $offset += $batchSize) {
        $end = [Math]::Min($offset + $batchSize - 1, $ports.Count - 1)
        $checks = @(
            foreach ($port in $ports[$offset..$end]) {
                $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
                try {
                    [pscustomobject]@{ Port = $port; Client = $client; Task = $client.ConnectAsync($address, $port) }
                } catch {
                    $client.Dispose()
                    Write-Host "${address}:${port} TCP error"
                }
            }
        )
        try {
            if ($checks.Count -gt 0) {
                $tasks = [Threading.Tasks.Task[]]@($checks | ForEach-Object { $_.Task })
                try { [void][Threading.Tasks.Task]::WaitAll($tasks, 2200) } catch [AggregateException] { }
            }
            foreach ($check in $checks) {
                $status = if ($check.Task.Status -eq 'RanToCompletion' -and $check.Client.Connected) {
                    [void]$open.Add($check.Port)
                    'TCP reachable'
                } elseif ($check.Task.IsFaulted) {
                    $err = $check.Task.Exception.GetBaseException()
                    if ($err -is [Net.Sockets.SocketException]) { "TCP $($err.SocketErrorCode)" } else { 'TCP failed' }
                } else {
                    'TCP timed out'
                }
                Write-Host "${address}:$($check.Port) $status"
            }
        } finally {
            foreach ($check in $checks) { $check.Client.Dispose() }
        }
    }
}
if ($open.Count) {
    Write-Host ('TCP reachable candidates: ' + (($open | Sort-Object) -join ','))
} else {
    Write-Host 'TCP reachable candidates: none'
}
Write-Host 'Use only ports assigned to this VPS. An HTTPS probe is required to confirm the NAT mapping and service identity.'
