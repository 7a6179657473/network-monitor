# Network and Process Monitor
# This script monitors active network connections and processes on the system

[CmdletBinding()]
param(
    [switch]$ShowProcesses,
    [switch]$ShowConnections,
    [switch]$ShowAll,
    [string]$OutputFormat = "Table",
    [string]$ExportPath,
    [int]$RefreshInterval = 0
)

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

# Function to display results
function Show-Results {
    param($Data, $Title)
    
    if ($Data) {
        Write-Host $Title -ForegroundColor White -BackgroundColor DarkBlue
        
        switch ($OutputFormat) {
            "Table" { $Data | Format-Table -AutoSize }
            "List" { $Data | Format-List }
            "Grid" { $Data | Out-GridView -Title $Title }
        }
        
        if ($ExportPath) {
            $exportFile = "$ExportPath\$($Title -replace '[^\w\s]', '_').csv"
            $Data | Export-Csv -Path $exportFile -NoTypeInformation
            Write-Host "Data exported to: $exportFile" -ForegroundColor Green
        }
    }
}

# Main execution
function Start-NetworkMonitor {
    Clear-Host
    Write-Host "Network and Process Monitor" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "Running on: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Gray
    Write-Host "=" * 60 -ForegroundColor Gray
    
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
            Start-Sleep -Seconds $RefreshInterval
            Clear-Host
        }
        
    } while ($RefreshInterval -gt 0)
}

# Run the monitor
Start-NetworkMonitor
