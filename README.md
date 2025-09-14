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

- **v1.0.0**: Initial release with basic network monitoring functionality
  - Active connection monitoring
  - Process network activity tracking
  - Multiple output formats
  - Export capabilities
  - Real-time monitoring support
