# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Network Monitor is a PowerShell-based tool for monitoring and analyzing network connections, processes, and system activity on Windows. The project consists of two main PowerShell scripts that work together to provide comprehensive network monitoring capabilities.

## Architecture

### Core Components
- **`NetworkMonitor.ps1`**: Main monitoring script with user interface and basic monitoring functions
- **`NetworkMonitorUtils.ps1`**: Advanced utility functions and specialized analysis tools

### Key Functions by File

**NetworkMonitor.ps1:**
- `Get-ActiveConnections`: Retrieves established TCP connections with process information
- `Get-NetworkProcesses`: Identifies processes with network activity and their resource usage
- `Get-ListeningPorts`: Lists services listening for incoming connections
- `Get-UDPConnections`: Monitors UDP endpoints
- `Show-Results`: Handles output formatting (Table, List, Grid) and CSV export
- `Start-NetworkMonitor`: Main orchestration function with refresh capability

**NetworkMonitorUtils.ps1:**
- `Get-NetworkStatistics`: Aggregated network connection statistics
- `Get-ConnectionsByPortRange`: Filter connections by port ranges
- `Get-ConnectionsByProcess`: Filter connections by process name
- `Get-SuspiciousConnections`: Security analysis for external/uncommon port connections
- `Get-ProcessNetworkUsage`: Performance counter-based bandwidth monitoring
- `Export-NetworkDataToJson`: Structured data export
- `New-NetworkReport`: HTML/JSON report generation

## Common Development Commands

### Running the Tool
```powershell
# Basic execution - shows all network information
.\NetworkMonitor.ps1

# Show only network connections
.\NetworkMonitor.ps1 -ShowConnections

# Show only processes with network activity
.\NetworkMonitor.ps1 -ShowProcesses

# Export data to CSV files
.\NetworkMonitor.ps1 -ShowAll -ExportPath "C:\Reports"

# Continuous monitoring with refresh
.\NetworkMonitor.ps1 -RefreshInterval 5
```

### Testing and Development
```powershell
# Load utility functions by dot-sourcing the script
. .\NetworkMonitorUtils.ps1
Get-NetworkStatistics
Get-SuspiciousConnections

# Test specific output formats
.\NetworkMonitor.ps1 -OutputFormat Grid
.\NetworkMonitor.ps1 -OutputFormat List

# Generate reports for testing (after dot-sourcing)
. .\NetworkMonitorUtils.ps1
New-NetworkReport -OutputPath "." -IncludeSuspicious -Format HTML
```

### PowerShell Environment Setup
```powershell
# Set execution policy if needed
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run as Administrator for complete process information
# Right-click PowerShell -> "Run as Administrator"
```

## Project-Specific Guidelines

### Code Structure
- Main user-facing functionality should be in `NetworkMonitor.ps1`
- Advanced/specialized utilities belong in `NetworkMonitorUtils.ps1`
- Both files use `[CmdletBinding()]` for proper PowerShell cmdlet behavior
- Error handling uses try-catch blocks with informative error messages

### Function Naming Conventions
- Use PowerShell-approved verbs (Get-, New-, Export-, Test-)
- Network data functions start with `Get-Network*` or `Get-Connections*`
- Report functions start with `New-*Report` or `Export-*`

### Data Structure Patterns
- Use `[PSCustomObject]@{}` for structured output objects
- Include process information (Name, ID, Path) in network connection objects
- Format memory usage in MB using `[math]::Round($process.WorkingSet64/1MB, 2)`
- Sort results by relevant fields (ProcessName, LocalPort, etc.)

### Output and Export Handling
- Support multiple output formats: Table (default), List, Grid
- CSV export functionality should be available for all major data types
- Use descriptive export filenames with timestamps
- Color-coded console output for different data types (Cyan, Green, Yellow, Magenta)

### Security Considerations
- The `Get-SuspiciousConnections` function identifies potentially suspicious external connections
- Default trusted subnets: localhost, RFC 1918 private ranges
- Administrator privileges recommended for complete process information
- Performance counters may require elevated permissions

### Performance Notes
- Large numbers of connections can impact performance
- Use specific switches (-ShowConnections, -ShowProcesses) for faster execution
- Refresh intervals should be adjustable based on system performance
- Performance counter access may require administrator privileges

### Error Handling Patterns
- Use `-ErrorAction SilentlyContinue` when process information might not be available
- Provide graceful degradation when running without administrator privileges
- Include meaningful error messages that guide users toward solutions

## Using NetworkMonitorUtils.ps1

The `NetworkMonitorUtils.ps1` file contains advanced utility functions that are not automatically available. To use these functions:

```powershell
# Dot-source the script to load functions into current session
. .\NetworkMonitorUtils.ps1

# Now you can use any of the utility functions
Get-NetworkStatistics
Get-SuspiciousConnections
Get-ConnectionsByPortRange -MinPort 8000 -MaxPort 9000 -LocalPort
Get-ConnectionsByProcess -ProcessName "chrome", "firefox"
New-NetworkReport -OutputPath "." -IncludeSuspicious -Format HTML
```

**Important**: The utility script is designed to be dot-sourced, not run directly or imported as a module.

## Dependencies and Requirements
- Windows PowerShell 5.1 or PowerShell Core 7.x
- Windows operating system
- Administrator privileges recommended for complete functionality
- Access to `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, and `Get-Process` cmdlets
