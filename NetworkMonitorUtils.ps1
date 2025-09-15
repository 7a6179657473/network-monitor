# Network Monitor Utility Functions
# Additional helper functions and advanced features for NetworkMonitor.ps1
# SECURITY: Enhanced with input validation, HTML sanitization, and path traversal protection

#Requires -ExecutionPolicy RemoteSigned

# Import System.Web for HTML encoding if available
try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
    $script:HtmlEncodeAvailable = $true
}
catch {
    $script:HtmlEncodeAvailable = $false
    Write-Warning "System.Web assembly not available. HTML encoding will use basic sanitization."
}

# Security logging function
function Write-SecurityLog {
    param(
        [Parameter(Mandatory)]
        [string]$Event,
        [string]$Details = "",
        [string]$Level = "INFO"
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Event - $Details"
        $logPath = Join-Path $env:TEMP "NetworkMonitor_Security.log"
        Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if logging fails
    }
}

# HTML sanitization function
function ConvertTo-SafeHtml {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )
    
    if ([string]::IsNullOrEmpty($Text)) {
        return ""
    }
    
    if ($script:HtmlEncodeAvailable) {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    }
    else {
        # Basic HTML encoding if System.Web is not available
        return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
    }
}

# Secure path validation function (same as main script)
function Test-SecureExportPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        # Resolve the full path
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        
        # Define allowed base directories
        $allowedPaths = @(
            [System.IO.Path]::GetFullPath($env:USERPROFILE),
            [System.IO.Path]::GetFullPath("C:\Temp"),
            [System.IO.Path]::GetFullPath("C:\Reports")
        )
        
        # Check if the path is within allowed directories
        $isAllowed = $false
        foreach ($allowedPath in $allowedPaths) {
            if ($fullPath.StartsWith($allowedPath, [StringComparison]::OrdinalIgnoreCase)) {
                $isAllowed = $true
                break
            }
        }
        
        if (-not $isAllowed) {
            Write-SecurityLog -Event "PATH_TRAVERSAL_ATTEMPT" -Details "Blocked path: $fullPath" -Level "WARNING"
            throw "Export path is outside allowed directories. Allowed: User Profile, C:\Temp, C:\Reports"
        }
        
        # Ensure directory exists and is writable
        if (-not (Test-Path $fullPath)) {
            try {
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            }
            catch {
                throw "Cannot create export directory: $fullPath"
            }
        }
        
        # Test write permissions
        $testFile = Join-Path $fullPath "test_permissions.tmp"
        try {
            "test" | Out-File -FilePath $testFile -ErrorAction Stop
            Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        }
        catch {
            throw "No write permission for directory: $fullPath"
        }
        
        Write-SecurityLog -Event "EXPORT_PATH_VALIDATED" -Details "Path: $fullPath"
        return $fullPath
    }
    catch {
        Write-SecurityLog -Event "EXPORT_PATH_VALIDATION_FAILED" -Details $_.Exception.Message -Level "ERROR"
        throw $_
    }
}

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

# Function to filter connections by port range with input validation
function Get-ConnectionsByPortRange {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 65535)]
        [int]$MinPort = 1,
        
        [ValidateRange(1, 65535)]
        [int]$MaxPort = 65535,
        
        [switch]$LocalPort,
        [switch]$RemotePort
    )
    
    # Validate port range logic
    if ($MinPort -gt $MaxPort) {
        Write-SecurityLog -Event "INVALID_PORT_RANGE" -Details "MinPort ($MinPort) > MaxPort ($MaxPort)" -Level "WARNING"
        throw "MinPort ($MinPort) cannot be greater than MaxPort ($MaxPort)"
    }
    
    Write-SecurityLog -Event "PORT_RANGE_FILTER" -Details "Range: $MinPort-$MaxPort, Local: $LocalPort, Remote: $RemotePort"
    
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

# Function to get connections by process name with input validation
function Get-ConnectionsByProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            foreach ($name in $_) {
                if ($name -match '[<>:"/\\|?*]') {
                    throw "Process name contains invalid characters: $name"
                }
            }
            return $true
        })]
        [string[]]$ProcessName
    )
    
    Write-SecurityLog -Event "PROCESS_FILTER" -Details "Processes: $($ProcessName -join ', ')"
    
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

# Function to export network data to JSON with secure path handling
function Export-NetworkDataToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath,
        
        [switch]$IncludeProcesses,
        [switch]$IncludeConnections,
        [switch]$IncludeStatistics
    )
    
    try {
        # Validate and secure the export path
        $securePath = Test-SecureExportPath -Path $ExportPath
        
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $exportData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            User = $env:USERNAME
            Data = @{}
        }
        
        Write-SecurityLog -Event "JSON_EXPORT_STARTED" -Details "Path: $securePath, Processes: $IncludeProcesses, Connections: $IncludeConnections, Stats: $IncludeStatistics"
    
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
        
        # Create secure file path
        $jsonFile = Join-Path $securePath "NetworkData_$timestamp.json"
        
        # Check if file exists
        if (Test-Path $jsonFile) {
            $response = Read-Host "File '$jsonFile' exists. Overwrite? (y/N)"
            if ($response -ne 'y' -and $response -ne 'Y') {
                Write-Host "Export cancelled by user." -ForegroundColor Yellow
                return $null
            }
        }
        
        # Export data securely
        $jsonContent = $exportData | ConvertTo-Json -Depth 5
        $jsonContent | Out-File -FilePath $jsonFile -Encoding UTF8 -ErrorAction Stop
        
        Write-Host "Network data exported securely to: $jsonFile" -ForegroundColor Green
        Write-SecurityLog -Event "JSON_EXPORT_COMPLETED" -Details "File: $jsonFile, Size: $($jsonContent.Length) chars"
        return $jsonFile
    }
    catch {
        Write-Error "Failed to export network data: $($_.Exception.Message)"
        Write-SecurityLog -Event "JSON_EXPORT_FAILED" -Details $_.Exception.Message -Level "ERROR"
        return $null
    }
}

# Function to generate secure network report with HTML sanitization
function New-NetworkReport {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = ".",
        
        [switch]$IncludeSuspicious,
        [switch]$IncludeStatistics,
        
        [ValidateSet("HTML", "JSON")]
        [string]$Format = "HTML"
    )
    
    try {
        # Validate and secure the output path
        $securePath = Test-SecureExportPath -Path $OutputPath
        
        Write-SecurityLog -Event "REPORT_GENERATION_STARTED" -Details "Path: $securePath, Format: $Format, Suspicious: $IncludeSuspicious"
    
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
                # Sanitize all user/system data for HTML output
                $safeComputer = ConvertTo-SafeHtml -Text $reportData.Computer
                $safeUser = ConvertTo-SafeHtml -Text $reportData.User
                $safeGenerated = ConvertTo-SafeHtml -Text $reportData.Generated.ToString()
                
                $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Monitor Report - $safeComputer</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1, h2 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        .stats { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .security-notice { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Monitor Report (Secure)</h1>
        <div class="security-notice">
            <p><strong>Security:</strong> This report has been generated with HTML sanitization and input validation.</p>
        </div>
        <div class="stats">
            <p><strong>Generated:</strong> $safeGenerated</p>
            <p><strong>Computer:</strong> $safeComputer</p>
            <p><strong>User:</strong> $safeUser</p>
        </div>
        
        <h2>Network Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Established Connections</td><td>$($reportData.Statistics.TotalEstablishedConnections)</td></tr>
            <tr><td>Listening Ports</td><td>$($reportData.Statistics.TotalListeningPorts)</td></tr>
            <tr><td>UDP Endpoints</td><td>$($reportData.Statistics.TotalUDPEndpoints)</td></tr>
            <tr><td>Unique Network Processes</td><td>$($reportData.Statistics.UniqueProcessesWithConnections)</td></tr>
        </table>
    </div>
</body>
</html>
"@
                $reportFile = Join-Path $securePath "NetworkReport_$timestamp.html"
                
                # Check if file exists
                if (Test-Path $reportFile) {
                    $response = Read-Host "File '$reportFile' exists. Overwrite? (y/N)"
                    if ($response -ne 'y' -and $response -ne 'Y') {
                        Write-Host "Report generation cancelled by user." -ForegroundColor Yellow
                        return $null
                    }
                }
                
                $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8 -ErrorAction Stop
            }
            
            "JSON" {
                $reportFile = Join-Path $securePath "NetworkReport_$timestamp.json"
                
                # Check if file exists
                if (Test-Path $reportFile) {
                    $response = Read-Host "File '$reportFile' exists. Overwrite? (y/N)"
                    if ($response -ne 'y' -and $response -ne 'Y') {
                        Write-Host "Report generation cancelled by user." -ForegroundColor Yellow
                        return $null
                    }
                }
                
                $reportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8 -ErrorAction Stop
            }
        }
        
        Write-Host "Network report generated securely: $reportFile" -ForegroundColor Green
        Write-SecurityLog -Event "REPORT_GENERATED" -Details "File: $reportFile, Format: $Format"
        return $reportFile
    }
    catch {
        Write-Error "Failed to generate network report: $($_.Exception.Message)"
        Write-SecurityLog -Event "REPORT_GENERATION_FAILED" -Details $_.Exception.Message -Level "ERROR"
        return $null
    }
}

# Functions exported by dot-sourcing this script
# Get-NetworkStatistics, Get-ConnectionsByPortRange, Get-ConnectionsByProcess,
# Get-SuspiciousConnections, Get-ProcessNetworkUsage, Export-NetworkDataToJson,
# New-NetworkReport
