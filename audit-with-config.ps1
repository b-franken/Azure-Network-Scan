<#
.SYNOPSIS
    Enterprise-Grade Azure Network & Private DNS Audit Script (Config-based Version)

.DESCRIPTION
    Production-ready audit script using centralized configuration file.
    All settings can be configured in audit-config.json.

    Features production-grade error handling with partial success mode - continues
    collecting remaining resources if individual collections fail.

.PARAMETER ConfigFile
    Path to JSON configuration file. Default: .\audit-config.json

.PARAMETER ShowConfig
    Display current configuration and exit

.PARAMETER DryRun
    Estimate resource counts and memory usage without collecting actual data.
    Useful for previewing audit scope in large environments before running full audit.

.EXAMPLE
    .\audit-with-config.ps1
    Runs full audit with default config file

.EXAMPLE
    .\audit-with-config.ps1 -DryRun
    Estimates resource counts without collecting data

.EXAMPLE
    .\audit-with-config.ps1 -ConfigFile "C:\configs\production-audit.json"
    Uses custom configuration file

.EXAMPLE
    .\audit-with-config.ps1 -ShowConfig
    Displays current configuration without running audit

.EXAMPLE
    $env:AZURE_CLIENT_SECRET = "your-secret"
    .\audit-with-config.ps1
    Uses service principal authentication with environment variable secret
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ".\audit-config.json",

    [Parameter(Mandatory = $false)]
    [switch]$ShowConfig,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"
$InformationPreference = "Continue"

$script:Constants = @{
    ESTIMATED_MEMORY_PER_RESOURCE_MB = 0.05
}

$script:ScriptVersion = "3.0.0-Config"
$script:StartTime = Get-Date
$script:Timestamp = $script:StartTime.ToString("yyyyMMdd_HHmmss")

$modulePath = Join-Path $PSScriptRoot "Modules"

Import-Module (Join-Path $modulePath "Core\AzureAudit.Config.psm1") -Force
Import-Module (Join-Path $modulePath "Core\AzureAudit.Logging.psm1") -Force
Import-Module (Join-Path $modulePath "Core\AzureAudit.Authentication.psm1") -Force
Import-Module (Join-Path $modulePath "DataCollection\AzureAudit.DataCollection.psm1") -Force
Import-Module (Join-Path $modulePath "Analysis\AzureAudit.Analysis.psm1") -Force
Import-Module (Join-Path $modulePath "AzureAudit.Reporting.psm1") -Force

Initialize-AuditConfig -ConfigFilePath $ConfigFile

if ($ShowConfig) {
    Show-AuditConfig
    exit 0
}

try {
    Test-AuditConfig
}
catch {
    Write-Information "Configuration validation failed:" -Tags @("Error")
    Write-Information $_.Exception.Message -Tags @("Error")
    Write-Information "`nRun with -ShowConfig to see current configuration" -Tags @("Warning")
    Write-Information "Or generate template: Export-AuditConfigTemplate -OutputPath '.\audit-config.json'" -Tags @("Warning")
    exit 1
}

$config = Get-AuditConfig

$outputPath = $config.Reporting.OutputPath
if ($PSCmdlet.ShouldProcess($outputPath, "Create output directory")) {
    if (!(Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }
}

$script:LogFilePath = Join-Path $outputPath "AuditLog_$script:Timestamp.log"

$script:AuditResults = @{
    VNets                     = @()
    PrivateDNSZones           = @()
    PrivateEndpoints          = @()
    VNetLinks                 = @()
    NSGs                      = @()
    RouteTables               = @()
    VPNGateways               = @()
    ExpressRouteCircuits      = @()
    AzureFirewalls            = @()
    ApplicationGateways       = @()
    LoadBalancers             = @()
    PublicIPs                 = @()
    BastionHosts              = @()
    PrivateLinkServices       = @()
    NATGateways               = @()
    DDoSPlans                 = @()
    DNSResolvers              = @()
    NetworkWatchers           = @()
    VirtualNetworkGateways    = @()
    Connections               = @()
    LocalNetworkGateways      = @()
    NetworkInterfaces         = @()
    VirtualHubs               = @()
    VirtualWANs               = @()
    FirewallPolicies          = @()
    ApplicationSecurityGroups = @()
    APIManagementServices     = @()
    TrafficManagerProfiles    = @()
    FrontDoorProfiles         = @()
    Issues                    = @{
        Critical = @()
        High     = @()
        Medium   = @()
        Low      = @()
        Info     = @()
    }
    Statistics                = @{
        TotalSubscriptions             = 0
        TotalVNets                     = 0
        TotalSubnets                   = 0
        TotalPrivateDNSZones           = 0
        TotalPrivateEndpoints          = 0
        TotalVNetLinks                 = 0
        TotalPeerings                  = 0
        TotalNSGs                      = 0
        TotalRouteTables               = 0
        TotalVPNGateways               = 0
        TotalExpressRouteCircuits      = 0
        TotalAzureFirewalls            = 0
        TotalApplicationGateways       = 0
        TotalLoadBalancers             = 0
        TotalPublicIPs                 = 0
        TotalBastionHosts              = 0
        TotalPrivateLinkServices       = 0
        TotalNATGateways               = 0
        TotalDDoSPlans                 = 0
        TotalDNSResolvers              = 0
        TotalNetworkWatchers           = 0
        TotalVirtualNetworkGateways    = 0
        TotalConnections               = 0
        TotalLocalNetworkGateways      = 0
        TotalNetworkInterfaces         = 0
        TotalVirtualHubs               = 0
        TotalVirtualWANs               = 0
        TotalFirewallPolicies          = 0
        TotalApplicationSecurityGroups = 0
        TotalAPIManagementServices     = 0
        TotalTrafficManagerProfiles    = 0
        TotalFrontDoorProfiles         = 0
        ExecutionTimeSeconds           = 0
        FailedCollections              = @()
    }
}

Write-Information "`n================================================================" -Tags @("Info")
Write-Information "  Azure Network & Private DNS Audit Script - v$script:ScriptVersion" -Tags @("Info")
Write-Information "================================================================`n" -Tags @("Info")

Initialize-AuditLogging -LogFilePath $script:LogFilePath -LogLevel $config.Logging.LogLevel

Write-AuditLog "Starting Azure Network Audit - Config-based Edition v$script:ScriptVersion" -Type Info
Write-AuditLog "Configuration file: $ConfigFile" -Type Info
Write-AuditLog "Log file: $script:LogFilePath" -Type Info
Write-AuditLog "Log level: $($config.Logging.LogLevel)" -Type Info

Write-AuditLog "Authenticating to Azure..." -Type Progress

try {
    if ($config.Authentication.AuthMethod -eq "AppRegistration") {
        Connect-AzureForAudit -ClientId $config.Authentication.ClientId `
            -ClientSecret $config.Authentication.ClientSecret `
            -TenantId $config.Authentication.TenantId
    }
    else {
        Connect-AzureForAudit
    }
}
catch {
    Write-AuditLog "Authentication failed: $($_.Exception.Message)" -Type Error
    exit 1
}

Write-AuditLog "Discovering Azure subscriptions..." -Type Progress

try {
    $subscriptions = Get-AuditSubscriptions -SubscriptionIds $config.Subscriptions.SubscriptionIds
    $script:AuditResults.Statistics.TotalSubscriptions = $subscriptions.Count
    Write-AuditLog "Found $($subscriptions.Count) enabled subscriptions to audit" -Type Success

    foreach ($sub in $subscriptions) {
        Write-AuditLog "  - $($sub.Name) ($($sub.Id))" -Type Debug
    }
}
catch {
    Write-AuditLog "Failed to retrieve subscriptions: $($_.Exception.Message)" -Type Error
    exit 1
}

$subscriptionIdList = $subscriptions.Id

if ($DryRun) {
    Write-Information "`n================================================================" -Tags @("Info")
    Write-Information "  DRY RUN MODE - Resource Count Estimation" -Tags @("Info")
    Write-Information "================================================================`n" -Tags @("Info")

    Write-AuditLog "Querying resource counts (no data will be collected)..." -Type Progress

    try {
        $estimateQuery = @"
Resources
| where type in (
    'microsoft.network/virtualnetworks',
    'microsoft.network/privatednszones',
    'microsoft.network/privateendpoints',
    'microsoft.network/privatednszones/virtualnetworklinks',
    'microsoft.network/networksecuritygroups',
    'microsoft.network/routetables',
    'microsoft.network/vpngateways',
    'microsoft.network/expressroutecircuits',
    'microsoft.network/azurefirewalls',
    'microsoft.network/applicationgateways',
    'microsoft.network/loadbalancers',
    'microsoft.network/publicipaddresses',
    'microsoft.network/bastionhosts',
    'microsoft.network/privatelinkservices',
    'microsoft.network/natgateways',
    'microsoft.network/ddosprotectionplans',
    'microsoft.network/dnsresolvers',
    'microsoft.network/networkwatchers',
    'microsoft.network/virtualnetworkgateways',
    'microsoft.network/connections',
    'microsoft.network/localnetworkgateways',
    'microsoft.network/networkinterfaces',
    'microsoft.network/virtualhubs',
    'microsoft.network/virtualwans',
    'microsoft.network/firewallpolicies',
    'microsoft.network/applicationsecuritygroups',
    'microsoft.apimanagement/service',
    'microsoft.network/trafficmanagerprofiles',
    'microsoft.network/frontdoors',
    'microsoft.cdn/profiles'
)
| where (type !~ 'microsoft.cdn/profiles') or
        (type =~ 'microsoft.cdn/profiles' and (properties.sku.name =~ 'Standard_AzureFrontDoor' or properties.sku.name =~ 'Premium_AzureFrontDoor'))
| summarize ResourceCount = count() by ResourceType = tolower(type)
| order by ResourceType asc
"@

        $estimates = Search-AzGraph -Query $estimateQuery -Subscription $subscriptionIdList

        Write-Information "`nEstimated Resource Counts:" -Tags @("Info")

        $totalResources = 0
        $typeMapping = @{
            'microsoft.network/virtualnetworks'                     = 'Virtual Networks'
            'microsoft.network/privatednszones'                     = 'Private DNS Zones'
            'microsoft.network/privateendpoints'                    = 'Private Endpoints'
            'microsoft.network/privatednszones/virtualnetworklinks' = 'VNet Links'
            'microsoft.network/networksecuritygroups'               = 'Network Security Groups'
            'microsoft.network/routetables'                         = 'Route Tables'
            'microsoft.network/vpngateways'                         = 'VPN Gateways'
            'microsoft.network/expressroutecircuits'                = 'ExpressRoute Circuits'
            'microsoft.network/azurefirewalls'                      = 'Azure Firewalls'
            'microsoft.network/applicationgateways'                 = 'Application Gateways'
            'microsoft.network/loadbalancers'                       = 'Load Balancers'
            'microsoft.network/publicipaddresses'                   = 'Public IP Addresses'
            'microsoft.network/bastionhosts'                        = 'Bastion Hosts'
            'microsoft.network/privatelinkservices'                 = 'Private Link Services'
            'microsoft.network/natgateways'                         = 'NAT Gateways'
            'microsoft.network/ddosprotectionplans'                 = 'DDoS Protection Plans'
            'microsoft.network/dnsresolvers'                        = 'DNS Resolvers'
            'microsoft.network/networkwatchers'                     = 'Network Watchers'
            'microsoft.network/virtualnetworkgateways'              = 'Virtual Network Gateways'
            'microsoft.network/connections'                         = 'Connections'
            'microsoft.network/localnetworkgateways'                = 'Local Network Gateways'
            'microsoft.network/networkinterfaces'                   = 'Network Interfaces'
            'microsoft.network/virtualhubs'                         = 'Virtual Hubs'
            'microsoft.network/virtualwans'                         = 'Virtual WANs'
            'microsoft.network/firewallpolicies'                    = 'Firewall Policies'
            'microsoft.network/applicationsecuritygroups'           = 'Application Security Groups'
            'microsoft.apimanagement/service'                       = 'API Management Services'
            'microsoft.network/trafficmanagerprofiles'              = 'Traffic Manager Profiles'
            'microsoft.network/frontdoors'                          = 'Front Door (Classic)'
            'microsoft.cdn/profiles'                                = 'Front Door (Standard/Premium)'
        }

        foreach ($estimate in $estimates) {
            $friendlyName = $typeMapping[$estimate.ResourceType] ?? $estimate.ResourceType
            $count = $estimate.ResourceCount ?? 0
            $totalResources += $count
            Write-Information "  - ${friendlyName}: $count" -Tags @("Info")
        }

        $estimatedMemoryMB = [Math]::Round($totalResources * $script:Constants.ESTIMATED_MEMORY_PER_RESOURCE_MB, 2)

        Write-Information "`nEstimated Statistics:" -Tags @("Info")
        Write-Information "  Total Resources: $totalResources" -Tags @("Info")
        Write-Information "  Estimated Memory Usage: ~${estimatedMemoryMB} MB" -Tags @("Info")
        Write-Information "  Estimated Collection Time: ~$([Math]::Ceiling($totalResources / 200)) minutes" -Tags @("Info")

        Write-Information "`nTo perform actual audit, run without -DryRun parameter`n" -Tags @("Success")

        exit 0
    }
    catch {
        Write-AuditLog "Dry run failed: $($_.Exception.Message)" -Type Error
        exit 1
    }
}

Write-AuditLog "Starting data collection via Azure Resource Graph..." -Type Progress
Write-AuditLog "This may take several minutes for large environments..." -Type Info

$collections = @(
    @{Name = "Virtual Networks"; FunctionName = "Get-VirtualNetworks"; TargetProperty = "VNets"; StatProperty = "TotalVNets" },
    @{Name = "Private DNS Zones"; FunctionName = "Get-PrivateDNSZones"; TargetProperty = "PrivateDNSZones"; StatProperty = "TotalPrivateDNSZones" },
    @{Name = "Private Endpoints"; FunctionName = "Get-PrivateEndpoints"; TargetProperty = "PrivateEndpoints"; StatProperty = "TotalPrivateEndpoints" },
    @{Name = "VNet Links"; FunctionName = "Get-VNetLinks"; TargetProperty = "VNetLinks"; StatProperty = "TotalVNetLinks" },
    @{Name = "Network Security Groups"; FunctionName = "Get-NetworkSecurityGroups"; TargetProperty = "NSGs"; StatProperty = "TotalNSGs" },
    @{Name = "Route Tables"; FunctionName = "Get-RouteTables"; TargetProperty = "RouteTables"; StatProperty = "TotalRouteTables" },
    @{Name = "VPN Gateways"; FunctionName = "Get-VPNGateways"; TargetProperty = "VPNGateways"; StatProperty = "TotalVPNGateways" },
    @{Name = "ExpressRoute Circuits"; FunctionName = "Get-ExpressRouteCircuits"; TargetProperty = "ExpressRouteCircuits"; StatProperty = "TotalExpressRouteCircuits" },
    @{Name = "Azure Firewalls"; FunctionName = "Get-AzureFirewalls"; TargetProperty = "AzureFirewalls"; StatProperty = "TotalAzureFirewalls" },
    @{Name = "Application Gateways"; FunctionName = "Get-ApplicationGateways"; TargetProperty = "ApplicationGateways"; StatProperty = "TotalApplicationGateways" },
    @{Name = "Load Balancers"; FunctionName = "Get-LoadBalancers"; TargetProperty = "LoadBalancers"; StatProperty = "TotalLoadBalancers" },
    @{Name = "Public IP Addresses"; FunctionName = "Get-PublicIPAddresses"; TargetProperty = "PublicIPs"; StatProperty = "TotalPublicIPs" },
    @{Name = "Bastion Hosts"; FunctionName = "Get-BastionHosts"; TargetProperty = "BastionHosts"; StatProperty = "TotalBastionHosts" },
    @{Name = "Private Link Services"; FunctionName = "Get-PrivateLinkServices"; TargetProperty = "PrivateLinkServices"; StatProperty = "TotalPrivateLinkServices" },
    @{Name = "NAT Gateways"; FunctionName = "Get-NATGateways"; TargetProperty = "NATGateways"; StatProperty = "TotalNATGateways" },
    @{Name = "DDoS Protection Plans"; FunctionName = "Get-DDoSProtectionPlans"; TargetProperty = "DDoSPlans"; StatProperty = "TotalDDoSPlans" },
    @{Name = "DNS Resolvers"; FunctionName = "Get-DNSResolvers"; TargetProperty = "DNSResolvers"; StatProperty = "TotalDNSResolvers" },
    @{Name = "Network Watchers"; FunctionName = "Get-NetworkWatchers"; TargetProperty = "NetworkWatchers"; StatProperty = "TotalNetworkWatchers" },
    @{Name = "Virtual Network Gateways"; FunctionName = "Get-VirtualNetworkGateways"; TargetProperty = "VirtualNetworkGateways"; StatProperty = "TotalVirtualNetworkGateways" },
    @{Name = "VPN Connections"; FunctionName = "Get-Connections"; TargetProperty = "Connections"; StatProperty = "TotalConnections" },
    @{Name = "Local Network Gateways"; FunctionName = "Get-LocalNetworkGateways"; TargetProperty = "LocalNetworkGateways"; StatProperty = "TotalLocalNetworkGateways" },
    @{Name = "Network Interfaces"; FunctionName = "Get-NetworkInterfaces"; TargetProperty = "NetworkInterfaces"; StatProperty = "TotalNetworkInterfaces" },
    @{Name = "Virtual Hubs"; FunctionName = "Get-VirtualHubs"; TargetProperty = "VirtualHubs"; StatProperty = "TotalVirtualHubs" },
    @{Name = "Virtual WANs"; FunctionName = "Get-VirtualWANs"; TargetProperty = "VirtualWANs"; StatProperty = "TotalVirtualWANs" },
    @{Name = "Firewall Policies"; FunctionName = "Get-FirewallPolicies"; TargetProperty = "FirewallPolicies"; StatProperty = "TotalFirewallPolicies" },
    @{Name = "Application Security Groups"; FunctionName = "Get-ApplicationSecurityGroups"; TargetProperty = "ApplicationSecurityGroups"; StatProperty = "TotalApplicationSecurityGroups" },
    @{Name = "API Management Services"; FunctionName = "Get-APIManagementServices"; TargetProperty = "APIManagementServices"; StatProperty = "TotalAPIManagementServices" },
    @{Name = "Traffic Manager Profiles"; FunctionName = "Get-TrafficManagerProfiles"; TargetProperty = "TrafficManagerProfiles"; StatProperty = "TotalTrafficManagerProfiles" },
    @{Name = "Front Door Profiles"; FunctionName = "Get-FrontDoorProfiles"; TargetProperty = "FrontDoorProfiles"; StatProperty = "TotalFrontDoorProfiles" }
)

$totalSteps = $collections.Count
$currentStep = 0
$successfulCollections = 0

foreach ($collection in $collections) {
    $currentStep++
    $percentComplete = [Math]::Round(($currentStep / $totalSteps) * 100, 0)

    Write-Progress -Activity "Azure Resource Collection" `
        -Status "Collecting $($collection.Name) ($currentStep of $totalSteps)" `
        -PercentComplete $percentComplete

    try {
        Write-AuditLog "Querying $($collection.Name)..." -Type Progress

        $result = & $collection.FunctionName -SubscriptionIds $subscriptionIdList `
            -PageSize $config.DataCollection.ResourceGraphPageSize `
            -ErrorAction Stop

        $script:AuditResults[$collection.TargetProperty] = $result
        $script:AuditResults.Statistics[$collection.StatProperty] = $result.Count ?? 0

        Write-AuditLog "Successfully retrieved $($result.Count ?? 0) $($collection.Name)" -Type Success
        $successfulCollections++
    }
    catch {
        Write-AuditLog "Failed to retrieve $($collection.Name): $($_.Exception.Message)" -Type Warning

        $script:AuditResults[$collection.TargetProperty] = @()
        $script:AuditResults.Statistics[$collection.StatProperty] = 0
        $script:AuditResults.Statistics.FailedCollections += $collection.Name
    }
}

Write-Progress -Activity "Azure Resource Collection" -Completed

$totalSubnets = 0
$totalPeerings = 0
$totalSubnets = ($script:AuditResults.VNets |
    Where-Object { $_.subnets } |
    ForEach-Object { $_.subnets.Count } |
    Measure-Object -Sum).Sum ?? 0

$totalPeerings = ($script:AuditResults.VNets |
    Where-Object { $_.peerings } |
    ForEach-Object { $_.peerings.Count } |
    Measure-Object -Sum).Sum ?? 0

$script:AuditResults.Statistics.TotalSubnets = $totalSubnets
$script:AuditResults.Statistics.TotalPeerings = $totalPeerings

Write-AuditLog "Data collection complete!" -Type Success
Write-AuditLog "  - VNets: $($script:AuditResults.Statistics.TotalVNets)" -Type Info
Write-AuditLog "  - Subnets: $($script:AuditResults.Statistics.TotalSubnets)" -Type Info
Write-AuditLog "  - Private DNS Zones: $($script:AuditResults.Statistics.TotalPrivateDNSZones)" -Type Info
Write-AuditLog "  - Private Endpoints: $($script:AuditResults.Statistics.TotalPrivateEndpoints)" -Type Info
Write-AuditLog "  - VNet Links: $($script:AuditResults.Statistics.TotalVNetLinks)" -Type Info
Write-AuditLog "  - VNet Peerings: $($script:AuditResults.Statistics.TotalPeerings)" -Type Info
Write-AuditLog "  - NSGs: $($script:AuditResults.Statistics.TotalNSGs)" -Type Info
Write-AuditLog "  - Route Tables: $($script:AuditResults.Statistics.TotalRouteTables)" -Type Info
Write-AuditLog "  - VPN Gateways: $($script:AuditResults.Statistics.TotalVPNGateways)" -Type Info
Write-AuditLog "  - ExpressRoute Circuits: $($script:AuditResults.Statistics.TotalExpressRouteCircuits)" -Type Info
Write-AuditLog "  - Azure Firewalls: $($script:AuditResults.Statistics.TotalAzureFirewalls)" -Type Info
Write-AuditLog "  - Application Gateways: $($script:AuditResults.Statistics.TotalApplicationGateways)" -Type Info
Write-AuditLog "  - Load Balancers: $($script:AuditResults.Statistics.TotalLoadBalancers)" -Type Info
Write-AuditLog "  - Public IPs: $($script:AuditResults.Statistics.TotalPublicIPs)" -Type Info
Write-AuditLog "  - Bastion Hosts: $($script:AuditResults.Statistics.TotalBastionHosts)" -Type Info
Write-AuditLog "  - Private Link Services: $($script:AuditResults.Statistics.TotalPrivateLinkServices)" -Type Info
Write-AuditLog "  - NAT Gateways: $($script:AuditResults.Statistics.TotalNATGateways)" -Type Info
Write-AuditLog "  - DDoS Protection Plans: $($script:AuditResults.Statistics.TotalDDoSPlans)" -Type Info
Write-AuditLog "  - DNS Resolvers: $($script:AuditResults.Statistics.TotalDNSResolvers)" -Type Info
Write-AuditLog "  - Network Watchers: $($script:AuditResults.Statistics.TotalNetworkWatchers)" -Type Info
Write-AuditLog "  - Virtual Network Gateways: $($script:AuditResults.Statistics.TotalVirtualNetworkGateways)" -Type Info
Write-AuditLog "  - VPN Connections: $($script:AuditResults.Statistics.TotalConnections)" -Type Info
Write-AuditLog "  - Local Network Gateways: $($script:AuditResults.Statistics.TotalLocalNetworkGateways)" -Type Info
Write-AuditLog "  - Network Interfaces: $($script:AuditResults.Statistics.TotalNetworkInterfaces)" -Type Info
Write-AuditLog "  - Virtual Hubs: $($script:AuditResults.Statistics.TotalVirtualHubs)" -Type Info
Write-AuditLog "  - Virtual WANs: $($script:AuditResults.Statistics.TotalVirtualWANs)" -Type Info
Write-AuditLog "  - Firewall Policies: $($script:AuditResults.Statistics.TotalFirewallPolicies)" -Type Info
Write-AuditLog "  - Application Security Groups: $($script:AuditResults.Statistics.TotalApplicationSecurityGroups)" -Type Info
Write-AuditLog "  - API Management Services: $($script:AuditResults.Statistics.TotalAPIManagementServices)" -Type Info
Write-AuditLog "  - Traffic Manager Profiles: $($script:AuditResults.Statistics.TotalTrafficManagerProfiles)" -Type Info
Write-AuditLog "  - Front Door Profiles: $($script:AuditResults.Statistics.TotalFrontDoorProfiles)" -Type Info

Write-AuditLog "Starting analysis phase..." -Type Progress

$analysisParams = @{
    VNets        = $script:AuditResults.VNets
    AuditResults = $script:AuditResults
}
Test-VNetProvisioningState @analysisParams

$overlapParams = @{
    VNets                = $script:AuditResults.VNets
    MaxConcurrentQueries = $config.Analysis.MaxConcurrentQueries
    AuditResults         = $script:AuditResults
}
Test-IPAddressOverlaps @overlapParams

Test-VNetPeerings @analysisParams

$dnsParams = @{
    PrivateDNSZones = $script:AuditResults.PrivateDNSZones
    AuditResults    = $script:AuditResults
}
Test-PrivateDNSZones @dnsParams

$vnetLinksParams = @{
    VNetLinks    = $script:AuditResults.VNetLinks
    VNets        = $script:AuditResults.VNets
    AuditResults = $script:AuditResults
}
Test-VNetLinks @vnetLinksParams

$endpointsParams = @{
    PrivateEndpoints = $script:AuditResults.PrivateEndpoints
    VNetLinks        = $script:AuditResults.VNetLinks
    AuditResults     = $script:AuditResults
}
Test-PrivateEndpoints @endpointsParams

Test-SubnetUtilization @analysisParams

$nsgParams = @{
    NSGs         = $script:AuditResults.NSGs
    AuditResults = $script:AuditResults
}
Test-NetworkSecurityGroups @nsgParams

$routeParams = @{
    RouteTables  = $script:AuditResults.RouteTables
    AuditResults = $script:AuditResults
}
Test-RouteTables @routeParams

Write-AuditLog "Analysis complete!" -Type Success

$totalIssues = ($script:AuditResults.Issues.Critical.Count ?? 0) +
($script:AuditResults.Issues.High.Count ?? 0) +
($script:AuditResults.Issues.Medium.Count ?? 0) +
($script:AuditResults.Issues.Low.Count ?? 0) +
($script:AuditResults.Issues.Info.Count ?? 0)

Write-AuditLog "Found $totalIssues total issues:" -Type Info
Write-AuditLog "  - Critical: $($script:AuditResults.Issues.Critical.Count ?? 0)" -Type $(if (($script:AuditResults.Issues.Critical.Count ?? 0) -gt 0) { "Error" } else { "Success" })
Write-AuditLog "  - High: $($script:AuditResults.Issues.High.Count ?? 0)" -Type $(if (($script:AuditResults.Issues.High.Count ?? 0) -gt 0) { "Warning" } else { "Success" })
Write-AuditLog "  - Medium: $($script:AuditResults.Issues.Medium.Count ?? 0)" -Type $(if (($script:AuditResults.Issues.Medium.Count ?? 0) -gt 0) { "Warning" } else { "Success" })
Write-AuditLog "  - Low: $($script:AuditResults.Issues.Low.Count ?? 0)" -Type Info
Write-AuditLog "  - Info: $($script:AuditResults.Issues.Info.Count ?? 0)" -Type Info

Write-AuditLog "Generating reports..." -Type Progress

$reportBasePath = Join-Path $outputPath "AzureNetworkAudit_$script:Timestamp"

$reportParams = @{
    AuditResults   = $script:AuditResults
    ReportBasePath = $reportBasePath
}
if ($config.Reporting.SkipHTMLReport) {
    $reportParams.SkipHTML = $true
}

$reportFiles = New-AuditReport @reportParams -WhatIf:$WhatIfPreference -Confirm:$false

$script:AuditResults.Statistics.ExecutionTimeSeconds = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)

Write-AuditLog "Execution time: $($script:AuditResults.Statistics.ExecutionTimeSeconds) seconds" -Type Info

Write-Information "`n================================================================" -Tags @("Success")
Write-Information "  AUDIT COMPLETE" -Tags @("Success")
Write-Information "================================================================`n" -Tags @("Success")

Write-Information "Data Collection Summary:" -Tags @("Info")
$failedCount = $script:AuditResults.Statistics.FailedCollections.Count ?? 0
if ($failedCount -eq 0) {
    Write-Information "  Status: All $totalSteps resource types collected successfully" -Tags @("Success")
}
else {
    Write-Information "  Status: $($totalSteps - $failedCount) of $totalSteps resource types collected" -Tags @("Warning")
    Write-Information "  Failed Collections:" -Tags @("Warning")
    foreach ($failed in $script:AuditResults.Statistics.FailedCollections) {
        Write-Information "    - $failed" -Tags @("Warning")
    }
}

Write-Information "`nResource Summary:" -Tags @("Info")
Write-Information "  - Subscriptions: $($script:AuditResults.Statistics.TotalSubscriptions ?? 0)" -Tags @("Info")
Write-Information "  - Virtual Networks: $($script:AuditResults.Statistics.TotalVNets ?? 0)" -Tags @("Info")
Write-Information "  - Subnets: $($script:AuditResults.Statistics.TotalSubnets ?? 0)" -Tags @("Info")
Write-Information "  - Private DNS Zones: $($script:AuditResults.Statistics.TotalPrivateDNSZones ?? 0)" -Tags @("Info")
Write-Information "  - Private Endpoints: $($script:AuditResults.Statistics.TotalPrivateEndpoints ?? 0)" -Tags @("Info")
Write-Information "  - VNet Links: $($script:AuditResults.Statistics.TotalVNetLinks ?? 0)" -Tags @("Info")
Write-Information "  - Execution Time: $($script:AuditResults.Statistics.ExecutionTimeSeconds)s" -Tags @("Info")

Write-Information "`nIssues Found:" -Tags @("Warning")
Write-Information "  - Critical: $($script:AuditResults.Issues.Critical.Count ?? 0)" -Tags @($(if (($script:AuditResults.Issues.Critical.Count ?? 0) -gt 0) { "Error" } else { "Success" }))
Write-Information "  - High: $($script:AuditResults.Issues.High.Count ?? 0)" -Tags @($(if (($script:AuditResults.Issues.High.Count ?? 0) -gt 0) { "Error" } else { "Success" }))
Write-Information "  - Medium: $($script:AuditResults.Issues.Medium.Count ?? 0)" -Tags @($(if (($script:AuditResults.Issues.Medium.Count ?? 0) -gt 0) { "Warning" } else { "Success" }))
Write-Information "  - Low: $($script:AuditResults.Issues.Low.Count ?? 0)" -Tags @("Info")
Write-Information "  - Info: $($script:AuditResults.Issues.Info.Count ?? 0)" -Tags @("Info")

Write-Information "`nReports:" -Tags @("Info")
Write-Information "  - Log File: $script:LogFilePath" -Tags @("Info")

if (($reportFiles.CSVFiles.Count ?? 0) -gt 0) {
    foreach ($file in $reportFiles.CSVFiles) {
        Write-Information "  - $(Split-Path $file -Leaf)" -Tags @("Info")
    }
}

if (($script:AuditResults.Issues.Critical.Count ?? 0) -gt 0) {
    Write-Information "`nCRITICAL ISSUES REQUIRE IMMEDIATE ATTENTION!" -Tags @("Error")
    Write-Information "Review: ${reportBasePath}_CriticalIssues.csv`n" -Tags @("Error")
}

if (($reportFiles.HTMLFiles.Count ?? 0) -gt 0) {
    $dashboardPath = $reportFiles.HTMLFiles[0]
    Write-Information "  - Interactive Dashboard: $dashboardPath" -Tags @("Success")

    if ($PSCmdlet.ShouldProcess($dashboardPath, "Open in browser")) {
        try {
            Start-Process $dashboardPath
            Write-AuditLog "Interactive dashboard opened in browser" -Type Success
        }
        catch {
            Write-AuditLog "Could not auto-open dashboard. Please open manually: $dashboardPath" -Type Info
        }
    }
}

if ($config.Reporting.Visualization.EnableNetworkGraphs) {
    Write-AuditLog "Generating network visualizations..." -Type Progress

    Import-Module (Join-Path $modulePath "AzureAudit.Visualization.psm1") -Force

    $visualizationParams = @{
        AuditResults   = $script:AuditResults
        OutputBasePath = $reportBasePath
        Formats        = $config.Reporting.Visualization.Formats
        GraphvizPath   = $config.Reporting.Visualization.GraphvizPath
    }

    if ($config.Reporting.Visualization.IncludeTimestamp) {
        $visualizationParams['IncludeTimestamp'] = $true
    }

    if ($PSCmdlet.ShouldProcess("Network Visualization", "Export visualization files")) {
        $visualizationFiles = Export-NetworkVisualization @visualizationParams
    }
    else {
        Write-AuditLog "Network visualization export skipped due to WhatIf" -Type Info
        $visualizationFiles = @()
    }

    Write-Information "`nNetwork Visualizations:" -Tags @("Info")
    foreach ($file in $visualizationFiles) {
        $fileName = Split-Path $file -Leaf
        Write-Information "  - $fileName" -Tags @("Info")
    }

    $interactiveHTML = $visualizationFiles | Where-Object { $_ -like "*Interactive.html" } | Select-Object -First 1
    if ($interactiveHTML -and (Test-Path $interactiveHTML)) {
        Write-Information "`n  Open this for interactive network map: $interactiveHTML" -Tags @("Success")
        Write-AuditLog "Interactive network visualization available: $interactiveHTML" -Type Success
    }
}

Write-AuditLog "Audit completed successfully" -Type Success
