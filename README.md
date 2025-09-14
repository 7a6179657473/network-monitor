# Network Monitor

A PowerShell script that monitors and displays active network connections, processes with network activity, and listening ports on Windows systems.

## Features

- **Active Network Connections**: Monitor established TCP connections with process information
- **Network Processes**: View processes that have network activity with resource usage
- **Listening Ports**: Display services listening for incoming connections
- **UDP Connections**: Monitor UDP endpoints and associated processes
- **Multiple Output Formats**: Table, List, or Grid view
- **Data Export**: Export results to CSV files
- **Real-time Monitoring**: Continuous monitoring with customizable refresh intervals

## Requirements

- Windows PowerShell 5.1 or PowerShell Core 7.x
- Windows operating system
- Administrator privileges (recommended for complete process information)

## Usage

### Basic Usage

```powershell
# Run the script with default settings (shows all information)
.\NetworkMonitor.ps1

# Show only network connections
.\NetworkMonitor.ps1 -ShowConnections

# Show only processes with network activity
.\NetworkMonitor.ps1 -ShowProcesses

# Show all information
.\NetworkMonitor.ps1 -ShowAll
```

### Advanced Usage

```powershell
# Display results in a grid view
.\NetworkMonitor.ps1 -OutputFormat Grid

# Display results as a list
.\NetworkMonitor.ps1 -OutputFormat List

# Export results to CSV files
.\NetworkMonitor.ps1 -ExportPath "C:\Reports"

# Continuous monitoring with 5-second refresh interval
.\NetworkMonitor.ps1 -RefreshInterval 5

# Combine multiple options
.\NetworkMonitor.ps1 -ShowAll -OutputFormat Grid -ExportPath "C:\Reports" -RefreshInterval 10
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ShowProcesses` | Switch | False | Display only processes with network activity |
| `-ShowConnections` | Switch | False | Display only network connections |
| `-ShowAll` | Switch | False | Display all information (connections, processes, listening ports) |
| `-OutputFormat` | String | "Table" | Output format: Table, List, or Grid |
| `-ExportPath` | String | None | Path to export CSV files |
| `-RefreshInterval` | Int | 0 | Refresh interval in seconds (0 = run once) |

## Output Information

### Active Connections
- Local and remote IP addresses and ports
- Connection state
- Associated process name and ID

### Network Processes
- Process name and ID
- CPU usage
- Memory usage (Working Set in MB)
- Start time
- Process path

### Listening Ports
- Local address and port
- Associated process information
- Service state

### UDP Connections
- Local address and port
- Associated process information

## Examples

### Monitor specific applications
```powershell
# Run the script and filter results for specific processes
.\NetworkMonitor.ps1 -ShowProcesses | Where-Object {$_.ProcessName -like "*chrome*"}
```

### Export network data for analysis
```powershell
# Export all network data to CSV files for later analysis
.\NetworkMonitor.ps1 -ShowAll -ExportPath "C:\NetworkReports"
```

### Real-time monitoring
```powershell
# Monitor network activity every 3 seconds
.\NetworkMonitor.ps1 -RefreshInterval 3
```

## Advanced Network Analysis with NetworkMonitorUtils.ps1

The `NetworkMonitorUtils.ps1` file provides advanced utility functions for detailed network analysis, security monitoring, and reporting. These functions offer capabilities beyond the basic monitoring script.

### Loading the Utility Functions

Before using any utility functions, you must dot-source the script to load the functions into your PowerShell session:

```powershell
# Load all utility functions into current session
. .\NetworkMonitorUtils.ps1
```

**Important**: Do not run `NetworkMonitorUtils.ps1` directly or try to import it as a module. Always use dot-sourcing (`. .\`).

### Available Utility Functions

#### 1. Get-NetworkStatistics
Provides aggregated statistics about network connections.

```powershell
# Load utilities first
. .\NetworkMonitorUtils.ps1

# Get network statistics
$stats = Get-NetworkStatistics
$stats

# Output example:
# TotalEstablishedConnections : 25
# TotalListeningPorts        : 45
# TotalUDPEndpoints          : 32
# UniqueProcessesWithConnections : 15
```

#### 2. Get-ConnectionsByPortRange
Filter connections by specific port ranges for targeted analysis.

```powershell
# Find connections on web server ports (80-443)
$webConnections = Get-ConnectionsByPortRange -MinPort 80 -MaxPort 443 -LocalPort
$webConnections | Format-Table

# Find connections to external services on high ports
$highPortConnections = Get-ConnectionsByPortRange -MinPort 8000 -MaxPort 9999 -RemotePort

# Find both local and remote connections in a specific range
$gameConnections = Get-ConnectionsByPortRange -MinPort 27000 -MaxPort 28000 -LocalPort -RemotePort
```

#### 3. Get-ConnectionsByProcess
Analyze network activity for specific processes.

```powershell
# Monitor browser connections
$browserConnections = Get-ConnectionsByProcess -ProcessName "chrome", "firefox", "msedge"
$browserConnections | Format-Table ProcessName, LocalPort, RemoteAddress, RemotePort

# Monitor specific application
$appConnections = Get-ConnectionsByProcess -ProcessName "slack"
$appConnections | Where-Object {$_.State -eq 'Established'}

# Monitor multiple system processes
$systemConnections = Get-ConnectionsByProcess -ProcessName "svchost", "services", "lsass"
```

#### 4. Get-SuspiciousConnections
Identify potentially suspicious network connections based on external IPs and uncommon ports.

```powershell
# Detect suspicious connections with default settings
$suspicious = Get-SuspiciousConnections
$suspicious | Format-Table ProcessName, RemoteAddress, RemotePort, SuspicionReason

# Custom trusted subnets and common ports
$customSuspicious = Get-SuspiciousConnections -TrustedSubnets @('127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16') -CommonPorts @(80, 443, 22, 3389)

# Export suspicious connections for security analysis
$suspicious | Export-Csv -Path "C:\Reports\SuspiciousConnections.csv" -NoTypeInformation
```

#### 5. Get-ProcessNetworkUsage
Monitor network I/O performance per process (requires elevated privileges).

```powershell
# Get network usage statistics
$networkUsage = Get-ProcessNetworkUsage
$networkUsage | Sort-Object NetworkIOBytesPerSec -Descending | Select-Object -First 10

# Monitor high network usage processes
$highUsage = $networkUsage | Where-Object {$_.NetworkIOBytesPerSec -gt 1000}
```

#### 6. Export-NetworkDataToJSON
Export comprehensive network data to structured JSON format.

```powershell
# Export all network data
$exportFile = Export-NetworkDataToJson -ExportPath "C:\Reports" -IncludeConnections -IncludeProcesses -IncludeStatistics

# Export only connection data
Export-NetworkDataToJson -ExportPath "." -IncludeConnections

# Export for automated analysis
$timestamp = Get-Date -Format "yyyy-MM-dd"
Export-NetworkDataToJson -ExportPath "C:\DailyReports\$timestamp" -IncludeProcesses -IncludeStatistics
```

#### 7. New-NetworkReport
Generate comprehensive HTML or JSON reports.

```powershell
# Generate HTML security report
$reportFile = New-NetworkReport -OutputPath "C:\Reports" -IncludeSuspicious -IncludeStatistics -Format HTML

# Generate JSON report for automation
New-NetworkReport -OutputPath "." -Format JSON

# Generate comprehensive security analysis report
New-NetworkReport -OutputPath "C:\SecurityReports" -IncludeSuspicious -IncludeStatistics -Format HTML
```

### Advanced Usage Examples

#### Security Monitoring Workflow
```powershell
# Load utilities
. .\NetworkMonitorUtils.ps1

# Step 1: Get baseline statistics
$stats = Get-NetworkStatistics
Write-Host "Total Connections: $($stats.TotalEstablishedConnections)"

# Step 2: Check for suspicious activity
$suspicious = Get-SuspiciousConnections
if ($suspicious.Count -gt 0) {
    Write-Warning "Found $($suspicious.Count) suspicious connections!"
    $suspicious | Format-Table ProcessName, RemoteAddress, RemotePort, SuspicionReason
}

# Step 3: Monitor high-traffic processes
$highTraffic = Get-ProcessNetworkUsage | Where-Object {$_.NetworkIOBytesPerSec -gt 500}
if ($highTraffic) {
    Write-Host "High network usage processes:" -ForegroundColor Yellow
    $highTraffic | Format-Table ProcessName, NetworkIOBytesPerSec
}

# Step 4: Generate security report
New-NetworkReport -OutputPath "." -IncludeSuspicious -Format HTML
```

#### Application-Specific Monitoring
```powershell
# Load utilities
. .\NetworkMonitorUtils.ps1

# Monitor web browsers
$browsers = @("chrome", "firefox", "msedge", "iexplore")
$browserConnections = Get-ConnectionsByProcess -ProcessName $browsers

# Analyze browser connection patterns
$externalConnections = $browserConnections | Where-Object {
    $_.RemoteAddress -notlike "127.*" -and 
    $_.RemoteAddress -notlike "192.168.*" -and
    $_.RemoteAddress -notlike "10.*"
}

Write-Host "External browser connections: $($externalConnections.Count)"
$externalConnections | Group-Object RemoteAddress | Sort-Object Count -Descending
```

#### Performance Analysis
```powershell
# Load utilities
. .\NetworkMonitorUtils.ps1

# Get network performance data
$networkUsage = Get-ProcessNetworkUsage
$topProcesses = $networkUsage | Sort-Object NetworkIOBytesPerSec -Descending | Select-Object -First 5

# Analyze port usage patterns
$portStats = Get-ConnectionsByPortRange -MinPort 1 -MaxPort 65535 -LocalPort |
    Group-Object LocalPort | 
    Sort-Object Count -Descending |
    Select-Object -First 10

Write-Host "Top 10 most used local ports:"
$portStats | Format-Table Name, Count
```

### Function Parameters and Options

| Function | Key Parameters | Description |
|----------|----------------|-------------|
| `Get-ConnectionsByPortRange` | `-MinPort`, `-MaxPort`, `-LocalPort`, `-RemotePort` | Filter by port ranges |
| `Get-ConnectionsByProcess` | `-ProcessName` (array) | Filter by process names |
| `Get-SuspiciousConnections` | `-TrustedSubnets`, `-CommonPorts` | Customize security analysis |
| `Export-NetworkDataToJson` | `-ExportPath`, `-IncludeConnections`, `-IncludeProcesses` | Control export content |
| `New-NetworkReport` | `-OutputPath`, `-IncludeSuspicious`, `-Format` | Report generation options |

### Error Handling and Requirements

- **Administrator Privileges**: Some functions (like `Get-ProcessNetworkUsage`) require elevated permissions
- **Performance Counters**: Network I/O monitoring may not be available on all systems
- **Memory Usage**: Large datasets may require sufficient system memory
- **Network Access**: Functions require access to network APIs and process information

### Integration with Main Script

You can combine utility functions with the main monitoring script:

```powershell
# Run main monitor and export detailed analysis
.\NetworkMonitor.ps1 -ShowAll -ExportPath "C:\Reports"

# Load utilities and generate additional reports
. .\NetworkMonitorUtils.ps1
New-NetworkReport -OutputPath "C:\Reports" -IncludeSuspicious -Format HTML
```

## File Structure

```
network-monitor/
├── NetworkMonitor.ps1          # Main monitoring script
├── NetworkMonitorUtils.ps1     # Utility functions and helpers
├── README.md                   # This documentation
└── .gitignore                  # Git ignore file
```

## Troubleshooting

### Common Issues

1. **Access Denied Errors**: Run PowerShell as Administrator for complete process information
2. **Execution Policy**: If scripts are blocked, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
3. **Missing Process Information**: Some system processes may require administrator privileges to view

### Performance Considerations

- Large numbers of connections may slow down the script
- Use specific switches (`-ShowConnections` or `-ShowProcesses`) for faster execution
- Adjust refresh intervals based on system performance

## Security Notes

- This script requires network and process information access
- Run with appropriate privileges for your security requirements
- Be cautious when exporting sensitive network information

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this network monitoring tool.

## License

This project is open source. Feel free to use and modify as needed.

## Version History

- **v1.1.0**: Enhanced documentation and utility functions
  - Comprehensive NetworkMonitorUtils.ps1 documentation
  - Advanced security monitoring examples
  - Performance analysis workflows
  - Fixed module export issues
  - Added WARP.md for development guidance

- **v1.0.0**: Initial release with basic network monitoring functionality
  - Active connection monitoring
  - Process network activity tracking
  - Multiple output formats
  - Export capabilities
  - Real-time monitoring support
