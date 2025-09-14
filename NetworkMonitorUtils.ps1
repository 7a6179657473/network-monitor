# Network Monitor Utility Functions
# Additional helper functions and advanced features for NetworkMonitor.ps1

# Function to get network statistics
function Get-NetworkStatistics {
    [CmdletBinding()]
    param()
    
    try {
        $stats = @{
            TotalEstablishedConnections = (Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}).Count
            TotalListeningPorts = (Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}).Count
            TotalUDPEndpoints = (Get-NetUDPEndpoint).Count
            UniqueProcessesWithConnections = (Get-NetTCPConnection | Select-Object OwningProcess -Unique).Count
        }
        
        return [PSCustomObject]$stats
    }
    catch {
        Write-Error "Failed to retrieve network statistics: $($_.Exception.Message)"
        return $null
    }
}

# Function to filter connections by port range
function Get-ConnectionsByPortRange {
    [CmdletBinding()]
    param(
        [int]$MinPort = 1,
        [int]$MaxPort = 65535,
        [switch]$LocalPort,
        [switch]$RemotePort
    )
    
    $connections = Get-NetTCPConnection
    
    if ($LocalPort) {
        $connections = $connections | Where-Object {$_.LocalPort -ge $MinPort -and $_.LocalPort -le $MaxPort}
    }
    
    if ($RemotePort) {
        $connections = $connections | Where-Object {$_.RemotePort -ge $MinPort -and $_.RemotePort -le $MaxPort}
    }
    
    return $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
                                     @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                                     @{Name='ProcessId';Expression={$_.OwningProcess}}
}

# Function to get connections by process name
function Get-ConnectionsByProcess {
    [CmdletBinding()]
    param(
        [string[]]$ProcessName
    )
    
    $results = @()
    
    foreach ($proc in $ProcessName) {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            $connections = Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq $process.Id}
            $results += $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
                                                   @{Name='ProcessName';Expression={$process.ProcessName}},
                                                   @{Name='ProcessId';Expression={$process.Id}}
        }
    }
    
    return $results
}

# Function to get suspicious connections (external IPs on uncommon ports)
function Get-SuspiciousConnections {
    [CmdletBinding()]
    param(
        [string[]]$TrustedSubnets = @('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'),
        [int[]]$CommonPorts = @(80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995)
    )
    
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
    $suspicious = @()
    
    foreach ($conn in $connections) {
        $isExternal = $true
        $remoteIP = $conn.RemoteAddress
        
        # Check if remote IP is in trusted subnets
        foreach ($subnet in $TrustedSubnets) {
            if (Test-IPInSubnet -IP $remoteIP -Subnet $subnet) {
                $isExternal = $false
                break
            }
        }
        
        # If external and not on common port, mark as suspicious
        if ($isExternal -and $conn.RemotePort -notin $CommonPorts) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $suspicious += [PSCustomObject]@{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State
                ProcessName = $process.ProcessName
                ProcessId = $conn.OwningProcess
                ProcessPath = $process.Path
                SuspicionReason = "External connection on uncommon port $($conn.RemotePort)"
            }
        }
    }
    
    return $suspicious
}

# Helper function to test if IP is in subnet
function Test-IPInSubnet {
    [CmdletBinding()]
    param(
        [string]$IP,
        [string]$Subnet
    )
    
    try {
        $subnetParts = $Subnet.Split('/')
        $networkIP = $subnetParts[0]
        $prefixLength = [int]$subnetParts[1]
        
        $ipBytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
        $networkBytes = ([System.Net.IPAddress]::Parse($networkIP)).GetAddressBytes()
        
        $mask = [uint32]0
        for ($i = 0; $i -lt $prefixLength; $i++) {
            $mask = $mask -bor (1 -shl (31 - $i))
        }
        
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        $networkInt = [BitConverter]::ToUInt32($networkBytes, 0)
        
        return (($ipInt -band $mask) -eq ($networkInt -band $mask))
    }
    catch {
        return $false
    }
}

# Function to get network bandwidth usage per process
function Get-ProcessNetworkUsage {
    [CmdletBinding()]
    param()
    
    try {
        $perfCounters = Get-Counter "\Process(*)\IO Data Bytes/sec" -ErrorAction SilentlyContinue
        $results = @()
        
        foreach ($counter in $perfCounters.CounterSamples) {
            $processName = ($counter.InstanceName -split '#')[0]
            if ($processName -ne '_total' -and $processName -ne 'idle') {
                $results += [PSCustomObject]@{
                    ProcessName = $processName
                    NetworkIOBytesPerSec = [math]::Round($counter.CookedValue, 2)
                }
            }
        }
        
        return $results | Sort-Object NetworkIOBytesPerSec -Descending
    }
    catch {
        Write-Warning "Performance counter access may require administrator privileges"
        return $null
    }
}

# Function to export network data to JSON
function Export-NetworkDataToJson {
    [CmdletBinding()]
    param(
        [string]$ExportPath,
        [switch]$IncludeProcesses,
        [switch]$IncludeConnections,
        [switch]$IncludeStatistics
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $exportData = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        Data = @{}
    }
    
    if ($IncludeConnections) {
        $exportData.Data.ActiveConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
                         @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                         @{Name='ProcessId';Expression={$_.OwningProcess}}
        
        $exportData.Data.ListeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
            Select-Object LocalAddress, LocalPort, State,
                         @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                         @{Name='ProcessId';Expression={$_.OwningProcess}}
    }
    
    if ($IncludeProcesses) {
        $exportData.Data.NetworkProcesses = Get-NetTCPConnection | 
            Select-Object OwningProcess -Unique | 
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    [PSCustomObject]@{
                        ProcessName = $process.ProcessName
                        ProcessId = $process.Id
                        CPU = $process.CPU
                        WorkingSet = [math]::Round($process.WorkingSet64/1MB, 2)
                        StartTime = $process.StartTime
                        Path = $process.Path
                    }
                }
            }
    }
    
    if ($IncludeStatistics) {
        $exportData.Data.Statistics = Get-NetworkStatistics
    }
    
    $jsonFile = Join-Path $ExportPath "NetworkData_$timestamp.json"
    $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
    
    Write-Host "Network data exported to: $jsonFile" -ForegroundColor Green
    return $jsonFile
}

# Function to generate network report
function New-NetworkReport {
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".",
        [switch]$IncludeSuspicious,
        [switch]$IncludeStatistics,
        [string]$Format = "HTML"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportData = @{
        Generated = Get-Date
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        Statistics = Get-NetworkStatistics
        ActiveConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object -First 20
        TopProcesses = Get-ProcessNetworkUsage | Select-Object -First 10
    }
    
    if ($IncludeSuspicious) {
        $reportData.SuspiciousConnections = Get-SuspiciousConnections
    }
    
    switch ($Format) {
        "HTML" {
            $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Monitor Report - $($reportData.Computer)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        .stats { background-color: #f8f9fa; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Network Monitor Report</h1>
    <div class="stats">
        <p><strong>Generated:</strong> $($reportData.Generated)</p>
        <p><strong>Computer:</strong> $($reportData.Computer)</p>
        <p><strong>User:</strong> $($reportData.User)</p>
    </div>
    
    <h2>Network Statistics</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Established Connections</td><td>$($reportData.Statistics.TotalEstablishedConnections)</td></tr>
        <tr><td>Listening Ports</td><td>$($reportData.Statistics.TotalListeningPorts)</td></tr>
        <tr><td>UDP Endpoints</td><td>$($reportData.Statistics.TotalUDPEndpoints)</td></tr>
    </table>
</body>
</html>
"@
            $reportFile = Join-Path $OutputPath "NetworkReport_$timestamp.html"
            $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        }
        
        "JSON" {
            $reportFile = Join-Path $OutputPath "NetworkReport_$timestamp.json"
            $reportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        }
    }
    
    Write-Host "Network report generated: $reportFile" -ForegroundColor Green
    return $reportFile
}

# Functions exported by dot-sourcing this script
# Get-NetworkStatistics, Get-ConnectionsByPortRange, Get-ConnectionsByProcess,
# Get-SuspiciousConnections, Get-ProcessNetworkUsage, Export-NetworkDataToJson,
# New-NetworkReport
