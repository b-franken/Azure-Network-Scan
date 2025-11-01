# Azure Network Audit Tool

PowerShell-based auditing tool for Azure network infrastructure. Scans subscriptions, identifies misconfigurations, and generates detailed reports with network topology visualizations.

## Requirements

- PowerShell 7.0 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.ResourceGraph
  - Az.Network
  - Az.PrivateDns
- Reader access to target Azure subscriptions
- Graphviz (optional, for SVG/PNG diagram generation)

Install required modules:

```powershell
Install-Module -Name Az.Accounts, Az.ResourceGraph, Az.Network, Az.PrivateDns -Scope CurrentUser
```

## Quick Start

Basic usage with interactive authentication:

```powershell
.\audit-with-config.ps1
```

The script will authenticate via browser and scan all accessible subscriptions. Reports are generated in the `AuditReports` directory.

## Configuration

The tool uses `audit-config.json` for configuration. Create this file from the example:

```json
{
  "Authentication": {
    "AuthMethod": "Interactive"
  },
  "Subscriptions": {
    "SubscriptionIds": []
  },
  "Reporting": {
    "OutputPath": ".\\AuditReports"
  }
}
```

### Authentication Methods

**Interactive (default):**
```json
{
  "Authentication": {
    "AuthMethod": "Interactive"
  }
}
```

**Service Principal (for automation):**
```json
{
  "Authentication": {
    "ClientId": "your-app-id",
    "TenantId": "your-tenant-id",
    "AuthMethod": "AppRegistration"
  }
}
```

Set the client secret via environment variable to avoid storing it in the config file:

```powershell
$env:AZURE_CLIENT_SECRET = "your-secret"
.\audit-with-config.ps1
```

### Subscription Filtering

Scan specific subscriptions:

```json
{
  "Subscriptions": {
    "SubscriptionIds": [
      "subscription-id-1",
      "subscription-id-2"
    ]
  }
}
```

Leave the array empty to scan all accessible subscriptions.

## Audited Resources

### Network Infrastructure
- Virtual Networks (address spaces, subnets, peering)
- Network Security Groups (rules, attachments)
- Route Tables (routes, BGP propagation)
- VPN Gateways and connections
- ExpressRoute circuits
- Azure Firewalls and policies
- Application Gateways
- Load Balancers (internal and external)
- Public IP addresses
- NAT Gateways
- Bastion Hosts

### DNS and Private Connectivity
- Private DNS Zones
- VNet-to-zone links
- Private Endpoints (connection status, DNS integration)
- DNS Resolvers

### Global Routing and Traffic Management
- API Management Services (VNet-injected instances)
- Traffic Manager Profiles (DNS-based load balancing)
- Azure Front Door (Classic and Standard/Premium)

### Network Monitoring
- Network Watchers
- DDoS Protection Plans

## Analysis and Checks

The tool performs the following validations:

**IP Address Management:**
- Detects overlapping CIDR ranges between VNets
- Identifies IPv6 address spaces (not validated for overlaps)
- Calculates subnet utilization

**Private DNS:**
- Finds duplicate zone names across subscriptions
- Identifies orphaned zones (no VNet links)
- Validates auto-registration configuration
- Checks for missing zone groups on private endpoints

**VNet Peering:**
- Verifies peering state (connected vs. disconnected)
- Detects invalid gateway transit configurations
- Validates remote gateway settings

**Network Security:**
- Identifies subnets without NSG protection
- Finds overly permissive inbound rules (0.0.0.0/0)
- Checks for disabled NSGs
- Validates route table attachments

**Resource State:**
- Checks provisioning state for all resources
- Identifies failed deployments

## Command-Line Options

**Show current configuration:**
```powershell
.\audit-with-config.ps1 -ShowConfig
```

**Dry run (estimate scope without collecting data):**
```powershell
.\audit-with-config.ps1 -DryRun
```

**Use custom config file:**
```powershell
.\audit-with-config.ps1 -ConfigFile C:\configs\production-audit.json
```

**WhatIf support:**
```powershell
.\audit-with-config.ps1 -WhatIf
```

## Output Reports

All reports are timestamped and saved to the configured output directory.

### CSV Reports
- `*_VNets.csv` - Virtual Network inventory
- `*_PrivateDNSZones.csv` - Private DNS zone details
- `*_PrivateEndpoints.csv` - Private endpoint inventory
- `*_AllIssues.csv` - All findings with severity levels

### HTML Reports
- `*_Dashboard.html` - Interactive dashboard with charts and filtering
- `*_NetworkGraph_Interactive.html` - D3.js network topology visualization

### Network Diagrams

When visualization is enabled, the following formats are generated:

| Format | Extension | Use Case |
|--------|-----------|----------|
| NetJSON | `.json` | Programmatic access, API integration |
| Graphviz DOT | `.dot` | Source file for diagram generation |
| SVG | `.svg` | Vector graphics for documentation |
| PNG | `.png` | Raster graphics for reports |
| Interactive HTML | `.html` | Browser-based exploration |
| Mermaid | `.mmd` | GitHub/GitLab markdown diagrams |
| Draw.io CSV | `.csv` | Import into diagrams.net for editing |

### Audit Log

Detailed execution log with timestamps: `AuditLog_<timestamp>.log`

Log levels: Debug, Info, Progress, Warning, Error, Success

## Issue Severity Levels

**Critical** 
- IP address overlaps between VNets
- Private endpoint DNS resolution failures
- Critical security misconfigurations

**High** 
- VNet peering in disconnected state
- Missing DNS zones for private endpoints
- Failed resource provisioning

**Medium** 
- High subnet utilization (>80%)
- Orphaned DNS zones
- Subnets without NSG protection

**Low** 
- Empty subnets
- Minor configuration issues

**Info** 
- IPv6 address spaces detected
- Capacity warnings
- Configuration notices

## Advanced Configuration

### Performance Tuning

For large environments (100+ VNets):

```json
{
  "DataCollection": {
    "ResourceGraphPageSize": 5000,
    "MaxRetries": 5,
    "BaseDelaySeconds": 2
  },
  "Analysis": {
    "MaxConcurrentQueries": 10,
    "ParallelProcessingThreshold": 100
  }
}
```

**ResourceGraphPageSize**: Number of resources per query (1000-5000)
**MaxRetries**: Retry attempts for throttled requests
**BaseDelaySeconds**: Initial delay for exponential backoff
**MaxConcurrentQueries**: Parallel threads for IP overlap analysis
**ParallelProcessingThreshold**: Minimum VNets to enable parallel processing

### Minimal Output

For fast scanning without reports:

```json
{
  "Reporting": {
    "SkipHTMLReport": true,
    "Visualization": {
      "EnableNetworkGraphs": false
    }
  }
}
```

### Logging Configuration

```json
{
  "Logging": {
    "LogLevel": "Debug",
    "LogToFile": true,
    "LogToConsole": true
  }
}
```

**LogLevel**: Debug, Info, Warning, Error
**LogToFile**: Save execution log
**LogToConsole**: Display progress in terminal

### Visualization Options

```json
{
  "Reporting": {
    "Visualization": {
      "EnableNetworkGraphs": true,
      "Formats": ["JSON", "DOT", "SVG", "PNG", "HTML", "Mermaid", "DrawIO"],
      "GraphvizPath": "dot",
      "HighlightIssues": true,
      "ColorScheme": "Azure",
      "GroupBySubscription": true
    }
  }
}
```

**Formats**: List of visualization formats to generate
**GraphvizPath**: Path to Graphviz dot executable
**HighlightIssues**: Color-code resources with issues
**GroupBySubscription**: Cluster VNets by subscription in diagrams

## Project Structure

```
Azure-Network-Map-1/
├── audit-with-config.ps1                  # Main entry point
├── audit-config.json                      # Configuration file
├── Modules/
│   ├── Core/
│   │   ├── AzureAudit.Authentication.psm1 # Azure authentication
│   │   ├── AzureAudit.Config.psm1         # Configuration management
│   │   └── AzureAudit.Logging.psm1        # Logging framework
│   ├── DataCollection/
│   │   └── AzureAudit.DataCollection.psm1 # Azure Resource Graph queries
│   ├── Analysis/
│   │   └── AzureAudit.Analysis.psm1       # Network analysis logic
│   ├── Reporting/
│   │   ├── AzureAudit.Reporting.psm1      # Report generation
│   │   ├── CSV/
│   │   │   └── AzureAudit.Reporting.CSV.psm1
│   │   └── HTML/
│   │       └── AzureAudit.Reporting.HTML.Components.psm1
│   └── Visualization/
│       ├── AzureAudit.Visualization.psm1  # Main visualization module
│       └── Exporters/
│           ├── AzureAudit.Visualization.JSON.psm1
│           ├── AzureAudit.Visualization.DOT.psm1
│           ├── AzureAudit.Visualization.HTML.psm1
│           ├── AzureAudit.Visualization.Mermaid.psm1
│           └── AzureAudit.Visualization.DrawIO.psm1
└── AuditReports/                          # Generated reports (created at runtime)
```

## Troubleshooting

### Authentication Errors

Verify Azure PowerShell connectivity:

```powershell
Connect-AzAccount
Get-AzSubscription
```

Check configuration:

```powershell
.\audit-with-config.ps1 -ShowConfig
```

### Missing Graphviz

Install Graphviz for SVG/PNG generation:

**Windows:**
```powershell
winget install Graphviz.Graphviz
```

**Linux/macOS:**
```bash
# Ubuntu/Debian
sudo apt install graphviz

# macOS
brew install graphviz
```

After installation, ensure `dot` is in PATH or specify the full path in config:

```json
{
  "Reporting": {
    "Visualization": {
      "GraphvizPath": "C:\\Program Files\\Graphviz\\bin\\dot.exe"
    }
  }
}
```

### Throttling or Timeout Errors

Increase retry settings in configuration:

```json
{
  "DataCollection": {
    "MaxRetries": 10,
    "BaseDelaySeconds": 5
  }
}
```

Enable debug logging to see retry attempts:

```json
{
  "Logging": {
    "LogLevel": "Debug"
  }
}
```

### Out of Memory

For very large environments, reduce scope:

1. Scan one subscription at a time
2. Disable visualization:
   ```json
   {
     "Reporting": {
       "Visualization": {
         "EnableNetworkGraphs": false
       }
     }
   }
   ```
3. Skip HTML reports:
   ```json
   {
     "Reporting": {
       "SkipHTMLReport": true
     }
   }
   ```

### Permission Issues

Required Azure RBAC permissions:
- Reader role on target subscriptions
- Access to Azure Resource Graph

Verify access:

```powershell
Search-AzGraph -Query "Resources | where type =~ 'microsoft.network/virtualnetworks' | take 1"
```

## Security Considerations

1. **Never commit audit-config.json with secrets to version control**
   - Add to `.gitignore`
   - Use environment variables for secrets
   - Use encrypted config format or Azure Key Vault

2. **Service Principal Permissions**
   - Assign Reader role only
   - Use dedicated service principal for auditing
   - Rotate secrets regularly

3. **Report Storage**
   - Audit reports may contain sensitive network topology information
   - Store reports in secure locations
   - Implement retention policies

4. **Execution Environment**
   - Run from trusted systems
   - Use Azure Key Vault for secret management in production
   - Enable audit logging for script execution

