# Network and Process Monitor
# This script monitors active network connections and processes on the system
# SECURITY: Enhanced with input validation and path traversal protection

#Requires -ExecutionPolicy RemoteSigned

[CmdletBinding()]
param(
    [switch]$ShowProcesses,
    [switch]$ShowConnections,
    [switch]$ShowAll,
    
    [ValidateSet("Table", "List", "Grid")]
    [string]$OutputFormat = "Table",
    
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -IsValid)) {
            throw "Invalid path format: $_"
        }
        return $true
    })]
    [string]$ExportPath,
    
    [ValidateRange(0, 300)]
    [int]$RefreshInterval = 0
)

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

# Secure path validation function
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

# Secure file write function
function Write-SecureFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object]$Data,
        [switch]$Force
    )
    
    try {
        # Validate the directory path
        $directory = Split-Path $Path -Parent
        $validatedPath = Test-SecureExportPath -Path $directory
        $securePath = Join-Path $validatedPath (Split-Path $Path -Leaf)
        
        # Check if file exists
        if ((Test-Path $securePath) -and -not $Force) {
            $response = Read-Host "File '$securePath' exists. Overwrite? (y/N)"
            if ($response -ne 'y' -and $response -ne 'Y') {
                Write-Host "Export cancelled by user." -ForegroundColor Yellow
                return $false
            }
        }
        
        # Write file securely
        $Data | Export-Csv -Path $securePath -NoTypeInformation -ErrorAction Stop
        
        Write-Host "Data exported securely to: $securePath" -ForegroundColor Green
        Write-SecurityLog -Event "FILE_EXPORTED" -Details "File: $securePath"
        return $true
    }
    catch {
        Write-Error "Failed to export data: $($_.Exception.Message)"
        Write-SecurityLog -Event "FILE_EXPORT_FAILED" -Details $_.Exception.Message -Level "ERROR"
        return $false
    }
}

# Function to get active network connections
function Get-ActiveConnections {
    Write-Host "`n=== ACTIVE NETWORK CONNECTIONS ===" -ForegroundColor Cyan
    
    try {
        $connections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | 
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
                         @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                         @{Name='ProcessId';Expression={$_.OwningProcess}}
        
        if ($connections) {
            return $connections | Sort-Object ProcessName
        } else {
            Write-Warning "No established TCP connections found."
            return $null
        }
    }
    catch {
        Write-Error "Failed to retrieve network connections: $($_.Exception.Message)"
        return $null
    }
}

# Function to get network-related processes
function Get-NetworkProcesses {
    Write-Host "`n=== PROCESSES WITH NETWORK ACTIVITY ===" -ForegroundColor Green
    
    try {
        # Get all processes that have network connections
        $networkProcesses = Get-NetTCPConnection | 
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
            } | Sort-Object ProcessName -Unique
        
        return $networkProcesses
    }
    catch {
        Write-Error "Failed to retrieve network processes: $($_.Exception.Message)"
        return $null
    }
}

# Function to get listening ports
function Get-ListeningPorts {
    Write-Host "`n=== LISTENING PORTS ===" -ForegroundColor Yellow
    
    try {
        $listeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
            Select-Object LocalAddress, LocalPort, State,
                         @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                         @{Name='ProcessId';Expression={$_.OwningProcess}} |
            Sort-Object LocalPort
        
        return $listeningPorts
    }
    catch {
        Write-Error "Failed to retrieve listening ports: $($_.Exception.Message)"
        return $null
    }
}

# Function to get UDP connections
function Get-UDPConnections {
    Write-Host "`n=== UDP CONNECTIONS ===" -ForegroundColor Magenta
    
    try {
        $udpConnections = Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort,
                         @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                         @{Name='ProcessId';Expression={$_.OwningProcess}} |
            Sort-Object LocalPort
        
        return $udpConnections
    }
    catch {
        Write-Error "Failed to retrieve UDP connections: $($_.Exception.Message)"
        return $null
    }
}

# Function to display results with secure export
function Show-Results {
    param(
        [Parameter(Mandatory)]
        [object]$Data,
        [Parameter(Mandatory)]
        [string]$Title
    )
    
    if ($Data) {
        Write-Host $Title -ForegroundColor White -BackgroundColor DarkBlue
        
        # Display data according to output format
        switch ($OutputFormat) {
            "Table" { 
                $Data | Format-Table -AutoSize
            }
            "List" { 
                $Data | Format-List
            }
            "Grid" { 
                try {
                    $Data | Out-GridView -Title $Title -ErrorAction Stop
                }
                catch {
                    Write-Warning "Grid view not available. Falling back to table format."
                    $Data | Format-Table -AutoSize
                }
            }
        }
        
        # Secure export if path is provided
        if ($ExportPath) {
            try {
                # Sanitize the title for filename
                $safeTitle = $Title -replace '[^\w\s-]', '_' -replace '\s+', '_'
                $exportFile = "$ExportPath\$safeTitle.csv"
                
                Write-SecurityLog -Event "EXPORT_ATTEMPT" -Details "File: $safeTitle.csv, Records: $($Data.Count)"
                
                $success = Write-SecureFile -Path $exportFile -Data $Data
                if (-not $success) {
                    Write-Warning "Export failed for $Title"
                }
            }
            catch {
                Write-Error "Export error for ${Title}: $($_.Exception.Message)"
                Write-SecurityLog -Event "EXPORT_ERROR" -Details "$Title - $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    else {
        Write-Host "$Title - No data available" -ForegroundColor Yellow
    }
}

# Main execution function with security enhancements
function Start-NetworkMonitor {
    # Log script execution
    Write-SecurityLog -Event "SCRIPT_STARTED" -Details "User: $env:USERNAME, Computer: $env:COMPUTERNAME, OutputFormat: $OutputFormat, ExportPath: $ExportPath"
    
    Clear-Host
    Write-Host "Network and Process Monitor (Secure)" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "Running on: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "User: $env:USERNAME" -ForegroundColor Gray
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Gray
    Write-Host "Security: Enhanced with path validation and input sanitization" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Gray
    
    do {
        if ($ShowAll -or $ShowConnections) {
            $connections = Get-ActiveConnections
            Show-Results $connections "ACTIVE_CONNECTIONS"
            
            $listeningPorts = Get-ListeningPorts
            Show-Results $listeningPorts "LISTENING_PORTS"
            
            $udpConnections = Get-UDPConnections
            Show-Results $udpConnections "UDP_CONNECTIONS"
        }
        
        if ($ShowAll -or $ShowProcesses) {
            $networkProcesses = Get-NetworkProcesses
            Show-Results $networkProcesses "NETWORK_PROCESSES"
        }
        
        # If no specific option is provided, show all
        if (-not ($ShowProcesses -or $ShowConnections)) {
            $connections = Get-ActiveConnections
            Show-Results $connections "ACTIVE_CONNECTIONS"
            
            $networkProcesses = Get-NetworkProcesses
            Show-Results $networkProcesses "NETWORK_PROCESSES"
            
            $listeningPorts = Get-ListeningPorts
            Show-Results $listeningPorts "LISTENING_PORTS"
        }
        
        if ($RefreshInterval -gt 0) {
            Write-Host "`nRefreshing in $RefreshInterval seconds... (Press Ctrl+C to stop)" -ForegroundColor Yellow
            try {
                Start-Sleep -Seconds $RefreshInterval
                Clear-Host
            }
            catch [System.Management.Automation.PipelineStoppedException] {
                Write-Host "`nMonitoring stopped by user." -ForegroundColor Yellow
                Write-SecurityLog -Event "MONITORING_STOPPED" -Details "User interrupted monitoring"
                break
            }
        }
        
    } while ($RefreshInterval -gt 0)
    
    Write-SecurityLog -Event "SCRIPT_COMPLETED" -Details "Normal completion"
}

# Run the monitor with error handling
try {
    Start-NetworkMonitor
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-SecurityLog -Event "SCRIPT_ERROR" -Details $_.Exception.Message -Level "ERROR"
    exit 1
}
