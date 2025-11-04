Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Constants = @{
    MaxRetryDelaySeconds = 60
    JitterMaxMilliseconds = 1000
    MillisecondsPerSecond = 1000
}

<#
.SYNOPSIS
    Executes a script block with exponential backoff retry logic.

.DESCRIPTION
    Invokes a script block and automatically retries on failure using exponential backoff with jitter.
    Handles throttling, timeouts, and transient errors with intelligent retry delays up to 60 seconds.
    Implements best practices for resilient Azure API calls.

.PARAMETER ScriptBlock
    The script block to execute with retry logic.

.PARAMETER MaxRetries
    Maximum number of retry attempts. Default is 5.

.PARAMETER BaseDelaySeconds
    Base delay in seconds for exponential backoff calculation. Default is 2 seconds.

.PARAMETER OperationName
    Name of the operation for logging purposes. Default is "Operation".

.OUTPUTS
    System.Object
    Returns the output of the executed script block.

.EXAMPLE
    $result = Invoke-WithRetry -ScriptBlock { Get-AzResource } -OperationName "Get Resources"
    Executes Get-AzResource with automatic retry on failure.

.EXAMPLE
    Invoke-WithRetry -ScriptBlock { Search-AzGraph -Query $query } -MaxRetries 3 -BaseDelaySeconds 1
    Executes Azure Resource Graph query with 3 retry attempts and 1 second base delay.

.NOTES
    Automatically detects throttling (429 errors) and timeout errors for intelligent retry handling.
    Uses exponential backoff with random jitter to prevent thundering herd problems.
    Maximum delay is capped at 60 seconds regardless of exponential calculation.
#>
function Invoke-WithRetry {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $false)]
        [int]$BaseDelaySeconds = 2,

        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Operation"
    )

    $attempt = 0

    while ($attempt -lt $MaxRetries) {
        try {
            $attempt++
            Write-AuditLog "Executing $OperationName (attempt $attempt/$MaxRetries)" -Type Debug
            return & $ScriptBlock
        }
        catch {
            $errorMessage = $_.Exception.Message

            if ($attempt -ge $MaxRetries) {
                Write-AuditLog "Failed $OperationName after $MaxRetries attempts: $errorMessage" -Type Error
                throw
            }

            $delay = [Math]::Min([Math]::Pow(2, $attempt - 1) * $BaseDelaySeconds, $script:Constants.MaxRetryDelaySeconds)

            if ($errorMessage -match '429|throttl|rate limit') {
                Write-AuditLog "Throttling detected for $OperationName. Waiting $delay seconds before retry $attempt/$MaxRetries" -Type Warning
            }
            elseif ($errorMessage -match 'timeout|timed out') {
                Write-AuditLog "Timeout detected for $OperationName. Waiting $delay seconds before retry $attempt/$MaxRetries" -Type Warning
            }
            else {
                Write-AuditLog "Error in $OperationName : $errorMessage. Waiting $delay seconds before retry $attempt/$MaxRetries" -Type Warning
            }

            $jitter = Get-Random -Minimum 0 -Maximum $script:Constants.JitterMaxMilliseconds
            $delayMilliseconds = [int]($delay * $script:Constants.MillisecondsPerSecond) + $jitter
            Start-Sleep -Milliseconds $delayMilliseconds
        }
    }
}

<#
.SYNOPSIS
    Executes Azure Resource Graph queries with automatic pagination and retry logic.

.DESCRIPTION
    Queries Azure Resource Graph across multiple subscriptions with automatic pagination handling.
    Retrieves all results by following skip tokens and implements retry logic for resilient execution.
    Provides detailed logging of pagination progress and total results retrieved.

.PARAMETER Query
    The Kusto Query Language (KQL) query to execute against Azure Resource Graph.

.PARAMETER SubscriptionIds
    Array of subscription IDs to query. Query will be executed across all specified subscriptions.

.PARAMETER QueryName
    Friendly name of the query for logging purposes. Default is "Query".

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000. Maximum is 1000 per Azure Resource Graph limits.

.OUTPUTS
    System.Array
    Returns an array of all results retrieved across all pages. Empty array if no results found.

.EXAMPLE
    $vnets = Invoke-AzResourceGraphWithPagination -Query "Resources | where type =~ 'microsoft.network/virtualnetworks'" -SubscriptionIds @("sub1", "sub2") -QueryName "Virtual Networks"
    Retrieves all virtual networks from specified subscriptions with pagination.

.EXAMPLE
    $resources = Invoke-AzResourceGraphWithPagination -Query $kqlQuery -SubscriptionIds $subs -PageSize 500
    Executes a custom query with 500 records per page.

.NOTES
    Automatically handles pagination using skip tokens from Azure Resource Graph.
    Implements retry logic through Invoke-WithRetry for resilient execution.
    Logs page count and total records retrieved for observability.
#>
function Invoke-AzResourceGraphWithPagination {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Query', Justification='Used in scriptblock passed to Invoke-WithRetry')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'SubscriptionIds', Justification='Used in scriptblock passed to Invoke-WithRetry')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [string]$QueryName = "Query",

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    Write-AuditLog "Executing paginated query: $QueryName" -Type Progress

    $allResults = @()
    $skipToken = $null
    $pageCount = 0
    $batchSize = $PageSize

    do {
        $pageCount++

        Write-Progress -Activity "Azure Resource Graph Query" -Status "Querying $QueryName (page $pageCount)..." -CurrentOperation "Processing pagination..."

        $result = Invoke-WithRetry -OperationName "$QueryName (page $pageCount)" -ScriptBlock {
            if ($skipToken) {
                Search-AzGraph -Query $Query -Subscription $SubscriptionIds -First $batchSize -SkipToken $skipToken
            }
            else {
                Search-AzGraph -Query $Query -Subscription $SubscriptionIds -First $batchSize
            }
        }

        if ($result -and $result.Count -gt 0) {
            $allResults += $result
            Write-AuditLog "Retrieved $($result.Count) records (page $pageCount, total: $($allResults.Count))" -Type Debug
            Write-Progress -Activity "Azure Resource Graph Query" -Status "Querying $QueryName" -CurrentOperation "Retrieved $($allResults.Count) records so far..."
        }

        $skipToken = $result.SkipToken

    } while ($skipToken)

    Write-Progress -Activity "Azure Resource Graph Query" -Completed

    Write-AuditLog "Completed $QueryName : Retrieved $($allResults.Count) total records across $pageCount pages" -Type Success

    return ,$allResults
}

<#
.SYNOPSIS
    Retrieves all Azure Virtual Networks from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual networks including their address spaces,
    subnets, peerings, DNS servers, and provisioning state. Returns comprehensive VNet configuration
    data for network topology mapping and analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for virtual networks.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of virtual network objects with properties: id, subscriptionId, resourceGroup,
    name, location, addressSpace, subnets, peerings, dnsServers, provisioningState, tags.

.EXAMPLE
    $vnets = Get-VirtualNetworks -SubscriptionIds @("sub1-guid", "sub2-guid")
    Retrieves all virtual networks from two subscriptions.

.EXAMPLE
    $vnets = Get-VirtualNetworks -SubscriptionIds $subscriptions -PageSize 500
    Retrieves virtual networks with custom page size.

.NOTES
    Returns detailed VNet properties including subnets and peering relationships.
    Essential for building network topology maps and dependency analysis.
#>
function Get-VirtualNetworks {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $vnetQuery = @"
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| extend addressSpace = properties.addressSpace.addressPrefixes
| extend subnets = properties.subnets
| extend peerings = properties.virtualNetworkPeerings
| extend dnsServers = properties.dhcpOptions.dnsServers
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, addressSpace, subnets, peerings, dnsServers, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $vnetQuery -SubscriptionIds $SubscriptionIds -QueryName "Virtual Networks" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Private DNS Zones from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all private DNS zones including record set counts,
    virtual network links, and registration link counts. Essential for DNS resolution mapping
    and private endpoint connectivity analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for private DNS zones.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of private DNS zone objects with properties: id, subscriptionId, resourceGroup,
    name, numberOfRecordSets, numberOfVirtualNetworkLinks, numberOfVirtualNetworkLinksWithRegistration, provisioningState.

.EXAMPLE
    $dnsZones = Get-PrivateDNSZones -SubscriptionIds @("sub1-guid")
    Retrieves all private DNS zones from specified subscription.

.EXAMPLE
    $dnsZones = Get-PrivateDNSZones -SubscriptionIds $subs -PageSize 500
    Retrieves private DNS zones with custom page size.

.NOTES
    Critical for mapping private endpoint DNS resolution and VNet DNS integration.
    Shows link counts for network associations and auto-registration.
#>
function Get-PrivateDNSZones {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $dnsQuery = @"
Resources
| where type =~ 'microsoft.network/privatednszones'
| extend numberOfRecordSets = toint(properties.numberOfRecordSets)
| extend numberOfVirtualNetworkLinks = toint(properties.numberOfVirtualNetworkLinks)
| extend numberOfVirtualNetworkLinksWithRegistration = toint(properties.numberOfVirtualNetworkLinksWithRegistration)
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, numberOfRecordSets, numberOfVirtualNetworkLinks, numberOfVirtualNetworkLinksWithRegistration, provisioningState
"@

    return Invoke-AzResourceGraphWithPagination -Query $dnsQuery -SubscriptionIds $SubscriptionIds -QueryName "Private DNS Zones" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Private Endpoints from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all private endpoints including subnet associations,
    private link service connections, group IDs, custom DNS configurations, and connection states.
    Critical for mapping private connectivity to Azure PaaS services.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for private endpoints.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of private endpoint objects with properties: id, subscriptionId, resourceGroup,
    name, location, subnetId, privateLinkServiceId, manualPrivateLinkServiceIds, groupIds,
    customDnsConfigs, networkInterfaces, provisioningState, connectionState.

.EXAMPLE
    $privateEndpoints = Get-PrivateEndpoints -SubscriptionIds @("sub1-guid")
    Retrieves all private endpoints from specified subscription.

.EXAMPLE
    $privateEndpoints = Get-PrivateEndpoints -SubscriptionIds $subs -PageSize 500
    Retrieves private endpoints with custom page size.

.NOTES
    Essential for mapping private connectivity from VNets to Azure services.
    Includes DNS configurations and connection approval states.
#>
function Get-PrivateEndpoints {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $peQuery = @"
Resources
| where type =~ 'microsoft.network/privateendpoints'
| extend subnetId = properties.subnet.id
| extend privateLinkServiceId = properties.privateLinkServiceConnections[0].properties.privateLinkServiceId
| extend manualPrivateLinkServiceIds = properties.manualPrivateLinkServiceConnections[0].properties.privateLinkServiceId
| extend groupIds = properties.privateLinkServiceConnections[0].properties.groupIds
| extend customDnsConfigs = properties.customDnsConfigs
| extend networkInterfaces = properties.networkInterfaces
| extend provisioningState = properties.provisioningState
| extend connectionState = properties.privateLinkServiceConnections[0].properties.privateLinkServiceConnectionState.status
| project id, subscriptionId, resourceGroup, name, location, subnetId, privateLinkServiceId, manualPrivateLinkServiceIds, groupIds, customDnsConfigs, networkInterfaces, provisioningState, connectionState
"@

    return Invoke-AzResourceGraphWithPagination -Query $peQuery -SubscriptionIds $SubscriptionIds -QueryName "Private Endpoints" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Private DNS Zone Virtual Network Links from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual network links for private DNS zones.
    Shows associations between private DNS zones and virtual networks including auto-registration
    settings and link states. Critical for DNS resolution topology mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for VNet links.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of VNet link objects with properties: id, subscriptionId, resourceGroup, name,
    zoneName, vnetId, registrationEnabled, linkState, provisioningState.

.EXAMPLE
    $vnetLinks = Get-VNetLinks -SubscriptionIds @("sub1-guid")
    Retrieves all private DNS zone VNet links from specified subscription.

.EXAMPLE
    $vnetLinks = Get-VNetLinks -SubscriptionIds $subs -PageSize 500
    Retrieves VNet links with custom page size.

.NOTES
    Maps DNS zone to VNet relationships for private DNS resolution.
    Shows auto-registration status for dynamic DNS record management.
#>
function Get-VNetLinks {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $linkQuery = @"
Resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| extend zoneName = tostring(split(id, '/')[8])
| extend vnetId = tostring(properties.virtualNetwork.id)
| extend registrationEnabled = properties.registrationEnabled
| extend linkState = properties.virtualNetworkLinkState
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, zoneName, vnetId, registrationEnabled, linkState, provisioningState
"@

    return Invoke-AzResourceGraphWithPagination -Query $linkQuery -SubscriptionIds $SubscriptionIds -QueryName "VNet Links" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Network Security Groups from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all network security groups including security rules,
    subnet associations, and network interface associations. Essential for security posture analysis
    and traffic flow mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for network security groups.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of NSG objects with properties: id, subscriptionId, resourceGroup, name, location,
    securityRules, subnets, networkInterfaces, provisioningState.

.EXAMPLE
    $nsgs = Get-NetworkSecurityGroups -SubscriptionIds @("sub1-guid")
    Retrieves all network security groups from specified subscription.

.EXAMPLE
    $nsgs = Get-NetworkSecurityGroups -SubscriptionIds $subs -PageSize 500
    Retrieves NSGs with custom page size.

.NOTES
    Includes all security rules and resource associations.
    Critical for security analysis and compliance auditing.
#>
function Get-NetworkSecurityGroups {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $nsgQuery = @"
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| extend securityRules = properties.securityRules
| extend subnets = properties.subnets
| extend networkInterfaces = properties.networkInterfaces
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, securityRules, subnets, networkInterfaces, provisioningState
"@

    return Invoke-AzResourceGraphWithPagination -Query $nsgQuery -SubscriptionIds $SubscriptionIds -QueryName "Network Security Groups" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Route Tables from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all route tables including custom routes,
    subnet associations, and BGP route propagation settings. Essential for traffic routing
    analysis and network path mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for route tables.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of route table objects with properties: id, subscriptionId, resourceGroup,
    name, location, routes, subnets, disableBgpRoutePropagation, provisioningState.

.EXAMPLE
    $routeTables = Get-RouteTables -SubscriptionIds @("sub1-guid")
    Retrieves all route tables from specified subscription.

.EXAMPLE
    $routeTables = Get-RouteTables -SubscriptionIds $subs -PageSize 500
    Retrieves route tables with custom page size.

.NOTES
    Includes all user-defined routes and subnet associations.
    Critical for understanding traffic flow and forced tunneling configurations.
#>
function Get-RouteTables {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $routeTableQuery = @"
Resources
| where type =~ 'microsoft.network/routetables'
| extend routes = properties.routes
| extend subnets = properties.subnets
| extend disableBgpRoutePropagation = properties.disableBgpRoutePropagation
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, routes, subnets, disableBgpRoutePropagation, provisioningState
"@

    return Invoke-AzResourceGraphWithPagination -Query $routeTableQuery -SubscriptionIds $SubscriptionIds -QueryName "Route Tables" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure VPN Gateways from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual network gateways including VPN configurations,
    SKU details, active-active settings, BGP settings, and VPN client configurations. Essential for
    hybrid connectivity and site-to-site VPN mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for VPN gateways.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of VPN gateway objects with properties: id, subscriptionId, resourceGroup, name,
    location, gatewayType, vpnType, sku, tier, activeActive, enableBgp, vpnClientConfiguration,
    provisioningState, tags.

.EXAMPLE
    $vpnGateways = Get-VPNGateways -SubscriptionIds @("sub1-guid")
    Retrieves all VPN gateways from specified subscription.

.EXAMPLE
    $vpnGateways = Get-VPNGateways -SubscriptionIds $subs -PageSize 500
    Retrieves VPN gateways with custom page size.

.NOTES
    Includes both VPN and ExpressRoute gateway types.
    Shows high availability and BGP configuration settings.
#>
function Get-VPNGateways {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $vpnQuery = @"
Resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| extend gatewayType = properties.gatewayType
| extend vpnType = properties.vpnType
| extend sku = properties.sku.name
| extend tier = properties.sku.tier
| extend activeActive = properties.activeActive
| extend enableBgp = properties.enableBgp
| extend vpnClientConfiguration = properties.vpnClientConfiguration
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, gatewayType, vpnType, sku, tier, activeActive, enableBgp, vpnClientConfiguration, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $vpnQuery -SubscriptionIds $SubscriptionIds -QueryName "VPN Gateways" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure ExpressRoute Circuits from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all ExpressRoute circuits including service provider details,
    peering locations, bandwidth, SKU tiers, billing models, and circuit provisioning states. Critical for
    dedicated private connectivity mapping and WAN analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for ExpressRoute circuits.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of ExpressRoute circuit objects with properties: id, subscriptionId, resourceGroup,
    name, location, serviceProviderName, peeringLocation, bandwidthInMbps, sku, billingModel,
    circuitProvisioningState, serviceProviderProvisioningState, peerings, provisioningState, tags.

.EXAMPLE
    $circuits = Get-ExpressRouteCircuits -SubscriptionIds @("sub1-guid")
    Retrieves all ExpressRoute circuits from specified subscription.

.EXAMPLE
    $circuits = Get-ExpressRouteCircuits -SubscriptionIds $subs -PageSize 500
    Retrieves ExpressRoute circuits with custom page size.

.NOTES
    Shows both Azure and service provider provisioning states.
    Includes peering configurations for private and Microsoft peerings.
#>
function Get-ExpressRouteCircuits {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $erQuery = @"
Resources
| where type =~ 'microsoft.network/expressroutecircuits'
| extend serviceProviderName = properties.serviceProviderProperties.serviceProviderName
| extend peeringLocation = properties.serviceProviderProperties.peeringLocation
| extend bandwidthInMbps = properties.serviceProviderProperties.bandwidthInMbps
| extend sku = properties.sku.tier
| extend billingModel = properties.sku.family
| extend circuitProvisioningState = properties.circuitProvisioningState
| extend serviceProviderProvisioningState = properties.serviceProviderProvisioningState
| extend peerings = properties.peerings
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, serviceProviderName, peeringLocation, bandwidthInMbps, sku, billingModel, circuitProvisioningState, serviceProviderProvisioningState, peerings, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $erQuery -SubscriptionIds $SubscriptionIds -QueryName "ExpressRoute Circuits" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Firewalls from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all Azure Firewalls including SKU tiers, threat intelligence
    modes, firewall policies, virtual hub associations, and IP configurations. Essential for centralized
    network security mapping and traffic inspection analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for Azure Firewalls.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Azure Firewall objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, threatIntelMode, firewallPolicy, virtualHub, ipConfigurations,
    provisioningState, tags.

.EXAMPLE
    $firewalls = Get-AzureFirewalls -SubscriptionIds @("sub1-guid")
    Retrieves all Azure Firewalls from specified subscription.

.EXAMPLE
    $firewalls = Get-AzureFirewalls -SubscriptionIds $subs -PageSize 500
    Retrieves Azure Firewalls with custom page size.

.NOTES
    Shows both hub-based and VNet-based firewall deployments.
    Includes threat intelligence and firewall policy associations.
#>
function Get-AzureFirewalls {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $firewallQuery = @"
Resources
| where type =~ 'microsoft.network/azurefirewalls'
| extend sku = properties.sku.tier
| extend threatIntelMode = properties.threatIntelMode
| extend firewallPolicy = properties.firewallPolicy.id
| extend virtualHub = properties.virtualHub.id
| extend ipConfigurations = properties.ipConfigurations
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, threatIntelMode, firewallPolicy, virtualHub, ipConfigurations, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $firewallQuery -SubscriptionIds $SubscriptionIds -QueryName "Azure Firewalls" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Application Gateways from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all application gateways including SKU details,
    capacity settings, autoscale configurations, WAF settings, and firewall policy associations.
    Essential for application delivery and web security analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for application gateways.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Application Gateway objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, tier, capacity, autoscaleConfiguration, wafEnabled, wafMode,
    firewallPolicy, provisioningState, tags.

.EXAMPLE
    $appGateways = Get-ApplicationGateways -SubscriptionIds @("sub1-guid")
    Retrieves all application gateways from specified subscription.

.EXAMPLE
    $appGateways = Get-ApplicationGateways -SubscriptionIds $subs -PageSize 500
    Retrieves application gateways with custom page size.

.NOTES
    Shows WAF configuration and autoscale settings.
    Critical for understanding application load balancing and web security posture.
#>
function Get-ApplicationGateways {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $appGwQuery = @"
Resources
| where type =~ 'microsoft.network/applicationgateways'
| extend sku = properties.sku.name
| extend tier = properties.sku.tier
| extend capacity = properties.sku.capacity
| extend autoscaleConfiguration = properties.autoscaleConfiguration
| extend wafEnabled = properties.webApplicationFirewallConfiguration.enabled
| extend wafMode = properties.webApplicationFirewallConfiguration.firewallMode
| extend firewallPolicy = properties.firewallPolicy.id
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, tier, capacity, autoscaleConfiguration, wafEnabled, wafMode, firewallPolicy, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $appGwQuery -SubscriptionIds $SubscriptionIds -QueryName "Application Gateways" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Load Balancers from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all load balancers including SKU details,
    frontend IP configurations, backend address pools, load balancing rules, and health probes.
    Essential for traffic distribution and high availability analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for load balancers.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Load Balancer objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, frontendIPConfigurations, backendAddressPools, loadBalancingRules,
    probes, provisioningState, tags.

.EXAMPLE
    $loadBalancers = Get-LoadBalancers -SubscriptionIds @("sub1-guid")
    Retrieves all load balancers from specified subscription.

.EXAMPLE
    $loadBalancers = Get-LoadBalancers -SubscriptionIds $subs -PageSize 500
    Retrieves load balancers with custom page size.

.NOTES
    Includes both internal and external load balancers.
    Shows complete configuration of frontend, backend, and rules.
#>
function Get-LoadBalancers {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $lbQuery = @"
Resources
| where type =~ 'microsoft.network/loadbalancers'
| extend sku = properties.sku.name
| extend frontendIPConfigurations = properties.frontendIPConfigurations
| extend backendAddressPools = properties.backendAddressPools
| extend loadBalancingRules = properties.loadBalancingRules
| extend probes = properties.probes
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, frontendIPConfigurations, backendAddressPools, loadBalancingRules, probes, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $lbQuery -SubscriptionIds $SubscriptionIds -QueryName "Load Balancers" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Public IP Addresses from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all public IP addresses including IP addresses,
    allocation methods, SKU details, associated resources, and DDoS protection settings.
    Essential for external connectivity mapping and security exposure analysis.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for public IP addresses.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Public IP Address objects with properties: id, subscriptionId, resourceGroup,
    name, location, ipAddress, publicIPAllocationMethod, sku, associatedResource,
    ddosProtectionCoverage, provisioningState, tags.

.EXAMPLE
    $publicIPs = Get-PublicIPAddresses -SubscriptionIds @("sub1-guid")
    Retrieves all public IP addresses from specified subscription.

.EXAMPLE
    $publicIPs = Get-PublicIPAddresses -SubscriptionIds $subs -PageSize 500
    Retrieves public IP addresses with custom page size.

.NOTES
    Shows resource associations to identify what services are exposed.
    Includes DDoS protection coverage information.
#>
function Get-PublicIPAddresses {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $pipQuery = @"
Resources
| where type =~ 'microsoft.network/publicipaddresses'
| extend ipAddress = properties.ipAddress
| extend publicIPAllocationMethod = properties.publicIPAllocationMethod
| extend sku = properties.sku.name
| extend associatedResource = properties.ipConfiguration.id
| extend ddosProtectionCoverage = properties.ddosSettings.protectionCoverage
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, ipAddress, publicIPAllocationMethod, sku, associatedResource, ddosProtectionCoverage, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $pipQuery -SubscriptionIds $SubscriptionIds -QueryName "Public IP Addresses" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Bastion Hosts from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all Bastion hosts including SKU details,
    IP configurations, and DNS names. Essential for secure VM access and jump box
    connectivity mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for Bastion hosts.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Bastion Host objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, ipConfigurations, dnsName, provisioningState, tags.

.EXAMPLE
    $bastions = Get-BastionHosts -SubscriptionIds @("sub1-guid")
    Retrieves all Bastion hosts from specified subscription.

.EXAMPLE
    $bastions = Get-BastionHosts -SubscriptionIds $subs -PageSize 500
    Retrieves Bastion hosts with custom page size.

.NOTES
    Shows secure RDP/SSH access points to virtual networks.
    Critical for understanding remote access patterns and security controls.
#>
function Get-BastionHosts {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $bastionQuery = @"
Resources
| where type =~ 'microsoft.network/bastionhosts'
| extend sku = properties.sku.name
| extend ipConfigurations = properties.ipConfigurations
| extend dnsName = properties.dnsName
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, ipConfigurations, dnsName, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $bastionQuery -SubscriptionIds $SubscriptionIds -QueryName "Bastion Hosts" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Private Link Services from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all private link services including load balancer
    frontend associations, IP configurations, visibility settings, auto-approval settings,
    and proxy protocol settings. Essential for private service exposure mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for private link services.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Private Link Service objects with properties: id, subscriptionId, resourceGroup,
    name, location, loadBalancerFrontendIpConfigurations, ipConfigurations, visibility,
    autoApproval, enableProxyProtocol, provisioningState, tags.

.EXAMPLE
    $privateLinkServices = Get-PrivateLinkServices -SubscriptionIds @("sub1-guid")
    Retrieves all private link services from specified subscription.

.EXAMPLE
    $privateLinkServices = Get-PrivateLinkServices -SubscriptionIds $subs -PageSize 500
    Retrieves private link services with custom page size.

.NOTES
    Shows services exposed for private endpoint connectivity.
    Includes visibility and auto-approval scope configurations.
#>
function Get-PrivateLinkServices {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $plsQuery = @"
Resources
| where type =~ 'microsoft.network/privatelinkservices'
| extend loadBalancerFrontendIpConfigurations = properties.loadBalancerFrontendIpConfigurations
| extend ipConfigurations = properties.ipConfigurations
| extend visibility = properties.visibility
| extend autoApproval = properties.autoApproval
| extend enableProxyProtocol = properties.enableProxyProtocol
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, loadBalancerFrontendIpConfigurations, ipConfigurations, visibility, autoApproval, enableProxyProtocol, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $plsQuery -SubscriptionIds $SubscriptionIds -QueryName "Private Link Services" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure NAT Gateways from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all NAT gateways including SKU details,
    idle timeout settings, public IP associations, public IP prefix associations, and
    subnet associations. Essential for outbound connectivity and SNAT mapping.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for NAT gateways.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of NAT Gateway objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, idleTimeoutInMinutes, publicIpAddresses, publicIpPrefixes,
    subnets, provisioningState, tags.

.EXAMPLE
    $natGateways = Get-NATGateways -SubscriptionIds @("sub1-guid")
    Retrieves all NAT gateways from specified subscription.

.EXAMPLE
    $natGateways = Get-NATGateways -SubscriptionIds $subs -PageSize 500
    Retrieves NAT gateways with custom page size.

.NOTES
    Shows outbound internet connectivity configuration for subnets.
    Includes public IP and prefix associations for SNAT pool analysis.
#>
function Get-NATGateways {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $natQuery = @"
Resources
| where type =~ 'microsoft.network/natgateways'
| extend sku = properties.sku.name
| extend idleTimeoutInMinutes = properties.idleTimeoutInMinutes
| extend publicIpAddresses = properties.publicIpAddresses
| extend publicIpPrefixes = properties.publicIpPrefixes
| extend subnets = properties.subnets
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, idleTimeoutInMinutes, publicIpAddresses, publicIpPrefixes, subnets, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $natQuery -SubscriptionIds $SubscriptionIds -QueryName "NAT Gateways" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure DDoS Protection Plans from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all DDoS protection plans including virtual network
    associations and provisioning states. Essential for understanding network DDoS protection
    coverage and security posture.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for DDoS protection plans.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of DDoS Protection Plan objects with properties: id, subscriptionId,
    resourceGroup, name, location, virtualNetworks, provisioningState, tags.

.EXAMPLE
    $ddosPlans = Get-DDoSProtectionPlans -SubscriptionIds @("sub1-guid")
    Retrieves all DDoS protection plans from specified subscription.

.EXAMPLE
    $ddosPlans = Get-DDoSProtectionPlans -SubscriptionIds $subs -PageSize 500
    Retrieves DDoS protection plans with custom page size.

.NOTES
    Shows virtual network associations for DDoS protection coverage.
    Critical for security and compliance assessments.
#>
function Get-DDoSProtectionPlans {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $ddosQuery = @"
Resources
| where type =~ 'microsoft.network/ddosprotectionplans'
| extend virtualNetworks = properties.virtualNetworks
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, virtualNetworks, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $ddosQuery -SubscriptionIds $SubscriptionIds -QueryName "DDoS Protection Plans" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure DNS Resolvers from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all DNS resolvers including virtual network
    associations and provisioning states. Essential for understanding DNS resolution
    architecture and hybrid DNS scenarios.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for DNS resolvers.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of DNS Resolver objects with properties: id, subscriptionId, resourceGroup,
    name, location, virtualNetwork, provisioningState, tags.

.EXAMPLE
    $dnsResolvers = Get-DNSResolvers -SubscriptionIds @("sub1-guid")
    Retrieves all DNS resolvers from specified subscription.

.EXAMPLE
    $dnsResolvers = Get-DNSResolvers -SubscriptionIds $subs -PageSize 500
    Retrieves DNS resolvers with custom page size.

.NOTES
    Shows DNS resolution infrastructure for hybrid scenarios.
    Critical for understanding DNS forwarding and conditional forwarding setups.
#>
function Get-DNSResolvers {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $resolverQuery = @"
Resources
| where type =~ 'microsoft.network/dnsresolvers'
| extend virtualNetwork = properties.virtualNetwork.id
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, virtualNetwork, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $resolverQuery -SubscriptionIds $SubscriptionIds -QueryName "DNS Resolvers" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Network Watchers from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all Network Watchers including their locations
    and provisioning states. Essential for understanding network monitoring capabilities
    and regional coverage.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for Network Watchers.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Network Watcher objects with properties: id, subscriptionId,
    resourceGroup, name, location, provisioningState, tags.

.EXAMPLE
    $networkWatchers = Get-NetworkWatchers -SubscriptionIds @("sub1-guid")
    Retrieves all Network Watchers from specified subscription.

.EXAMPLE
    $networkWatchers = Get-NetworkWatchers -SubscriptionIds $subs -PageSize 500
    Retrieves Network Watchers with custom page size.

.NOTES
    Shows regional network monitoring infrastructure deployment.
    One Network Watcher is typically deployed per Azure region.
#>
function Get-NetworkWatchers {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $nwQuery = @"
Resources
| where type =~ 'microsoft.network/networkwatchers'
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $nwQuery -SubscriptionIds $SubscriptionIds -QueryName "Network Watchers" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Virtual Network Gateways from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual network gateways (VPN and ExpressRoute gateways)
    including their type, SKU, active-active configuration, BGP settings, and connection information.
    Essential for mapping hybrid connectivity and site-to-site VPN topologies.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for virtual network gateways.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of virtual network gateway objects with properties: id, subscriptionId, resourceGroup,
    name, location, gatewayType, vpnType, sku, tier, activeActive, enableBgp, bgpSettings, vnetId, provisioningState, tags.

.EXAMPLE
    $vngws = Get-VirtualNetworkGateways -SubscriptionIds @("sub1-guid")
    Retrieves all virtual network gateways from specified subscription.

.EXAMPLE
    $vngws = Get-VirtualNetworkGateways -SubscriptionIds $subs -PageSize 500
    Retrieves virtual network gateways with custom page size.

.NOTES
    Critical for mapping VPN and ExpressRoute connectivity to on-premises networks.
    Shows gateway SKU, BGP configuration, and associated virtual network.
#>
function Get-VirtualNetworkGateways {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $vngwQuery = @"
Resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| extend gatewayType = properties.gatewayType
| extend vpnType = properties.vpnType
| extend sku = properties.sku.name
| extend tier = properties.sku.tier
| extend activeActive = properties.activeActive
| extend enableBgp = properties.enableBgp
| extend bgpSettings = properties.bgpSettings
| extend vnetId = tostring(properties.ipConfigurations[0].properties.subnet.id)
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, gatewayType, vpnType, sku, tier, activeActive, enableBgp, bgpSettings, vnetId, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $vngwQuery -SubscriptionIds $SubscriptionIds -QueryName "Virtual Network Gateways" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Gateway Connections from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all connection objects between virtual network gateways
    and local network gateways or other virtual network gateways. Includes IPsec/IKE policy,
    connection type, status, and bandwidth information.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for connections.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of connection objects with properties: id, subscriptionId, resourceGroup, name, location,
    connectionType, connectionProtocol, routingWeight, sharedKey presence, virtualNetworkGateway1,
    virtualNetworkGateway2, localNetworkGateway2, connectionStatus, egressBytesTransferred,
    ingressBytesTransferred, provisioningState, tags.

.EXAMPLE
    $connections = Get-Connections -SubscriptionIds @("sub1-guid")
    Retrieves all gateway connections from specified subscription.

.EXAMPLE
    $connections = Get-Connections -SubscriptionIds $subs -PageSize 500
    Retrieves connections with custom page size.

.NOTES
    Essential for understanding VPN tunnel status and ExpressRoute circuit connections.
    Shows connection health, bandwidth usage, and gateway associations.
#>
function Get-Connections {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $connQuery = @"
Resources
| where type =~ 'microsoft.network/connections'
| extend connectionType = properties.connectionType
| extend connectionProtocol = properties.connectionProtocol
| extend routingWeight = properties.routingWeight
| extend sharedKey = isnotempty(properties.sharedKey)
| extend virtualNetworkGateway1 = properties.virtualNetworkGateway1.id
| extend virtualNetworkGateway2 = properties.virtualNetworkGateway2.id
| extend localNetworkGateway2 = properties.localNetworkGateway2.id
| extend connectionStatus = properties.connectionStatus
| extend egressBytesTransferred = properties.egressBytesTransferred
| extend ingressBytesTransferred = properties.ingressBytesTransferred
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, connectionType, connectionProtocol, routingWeight, sharedKey, virtualNetworkGateway1, virtualNetworkGateway2, localNetworkGateway2, connectionStatus, egressBytesTransferred, ingressBytesTransferred, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $connQuery -SubscriptionIds $SubscriptionIds -QueryName "Gateway Connections" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Local Network Gateways from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all local network gateway resources representing
    on-premises network locations. Includes gateway IP address, address space, and BGP settings.
    Essential for understanding site-to-site VPN topology.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for local network gateways.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of local network gateway objects with properties: id, subscriptionId, resourceGroup,
    name, location, gatewayIpAddress, addressPrefixes, bgpSettings, provisioningState, tags.

.EXAMPLE
    $lngws = Get-LocalNetworkGateways -SubscriptionIds @("sub1-guid")
    Retrieves all local network gateways from specified subscription.

.EXAMPLE
    $lngws = Get-LocalNetworkGateways -SubscriptionIds $subs -PageSize 500
    Retrieves local network gateways with custom page size.

.NOTES
    Represents on-premises networks in site-to-site VPN configurations.
    Shows remote network address spaces and gateway endpoints.
#>
function Get-LocalNetworkGateways {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $lngwQuery = @"
Resources
| where type =~ 'microsoft.network/localnetworkgateways'
| extend gatewayIpAddress = properties.gatewayIpAddress
| extend addressPrefixes = properties.localNetworkAddressSpace.addressPrefixes
| extend bgpSettings = properties.bgpSettings
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, gatewayIpAddress, addressPrefixes, bgpSettings, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $lngwQuery -SubscriptionIds $SubscriptionIds -QueryName "Local Network Gateways" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Network Interfaces from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all network interface resources attached to VMs
    and other compute resources. Includes IP configurations, subnet associations, NSG attachments,
    and VM associations. Critical for mapping VM-to-network relationships.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for network interfaces.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of network interface objects with properties: id, subscriptionId, resourceGroup,
    name, location, ipConfigurations, networkSecurityGroup, virtualMachine, primary, provisioningState, tags.

.EXAMPLE
    $nics = Get-NetworkInterfaces -SubscriptionIds @("sub1-guid")
    Retrieves all network interfaces from specified subscription.

.EXAMPLE
    $nics = Get-NetworkInterfaces -SubscriptionIds $subs -PageSize 500
    Retrieves network interfaces with custom page size.

.NOTES
    Essential for understanding which VMs are attached to which subnets and VNets.
    Shows IP addresses, NSG associations, and load balancer backend pool membership.
#>
function Get-NetworkInterfaces {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $nicQuery = @"
Resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend ipConfigurations = properties.ipConfigurations
| extend networkSecurityGroup = properties.networkSecurityGroup.id
| extend virtualMachine = properties.virtualMachine.id
| extend primary = properties.primary
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, ipConfigurations, networkSecurityGroup, virtualMachine, primary, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $nicQuery -SubscriptionIds $SubscriptionIds -QueryName "Network Interfaces" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Virtual Hubs from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual hub resources in Azure Virtual WAN.
    Includes address prefix, routing state, security provider, and connected resources.
    Essential for mapping Virtual WAN hub-spoke topologies.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for virtual hubs.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of virtual hub objects with properties: id, subscriptionId, resourceGroup, name,
    location, addressPrefix, virtualWan, routingState, securityProviderName, virtualHubRouteTableV2s,
    provisioningState, tags.

.EXAMPLE
    $vhubs = Get-VirtualHubs -SubscriptionIds @("sub1-guid")
    Retrieves all virtual hubs from specified subscription.

.EXAMPLE
    $vhubs = Get-VirtualHubs -SubscriptionIds $subs -PageSize 500
    Retrieves virtual hubs with custom page size.

.NOTES
    Part of Azure Virtual WAN architecture for global transit network connectivity.
    Shows hub address space, routing configuration, and connected networks.
#>
function Get-VirtualHubs {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $vhubQuery = @"
Resources
| where type =~ 'microsoft.network/virtualhubs'
| extend addressPrefix = properties.addressPrefix
| extend virtualWan = properties.virtualWan.id
| extend routingState = properties.routingState
| extend securityProviderName = properties.securityProviderName
| extend virtualHubRouteTableV2s = properties.virtualHubRouteTableV2s
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, addressPrefix, virtualWan, routingState, securityProviderName, virtualHubRouteTableV2s, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $vhubQuery -SubscriptionIds $SubscriptionIds -QueryName "Virtual Hubs" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Virtual WANs from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all virtual WAN resources representing global
    transit network architectures. Includes WAN type, security provider, and connected hubs.
    Top-level resource for Azure Virtual WAN deployments.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for virtual WANs.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of virtual WAN objects with properties: id, subscriptionId, resourceGroup, name,
    location, wanType, securityProviderName, allowBranchToBranchTraffic, allowVnetToVnetTraffic,
    provisioningState, tags.

.EXAMPLE
    $vwans = Get-VirtualWANs -SubscriptionIds @("sub1-guid")
    Retrieves all virtual WANs from specified subscription.

.EXAMPLE
    $vwans = Get-VirtualWANs -SubscriptionIds $subs -PageSize 500
    Retrieves virtual WANs with custom page size.

.NOTES
    Represents the top-level global network architecture in Virtual WAN deployments.
    Shows WAN type (Basic vs Standard) and traffic flow permissions.
#>
function Get-VirtualWANs {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $vwanQuery = @"
Resources
| where type =~ 'microsoft.network/virtualwans'
| extend wanType = properties.type
| extend securityProviderName = properties.securityProviderName
| extend allowBranchToBranchTraffic = properties.allowBranchToBranchTraffic
| extend allowVnetToVnetTraffic = properties.allowVnetToVnetTraffic
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, wanType, securityProviderName, allowBranchToBranchTraffic, allowVnetToVnetTraffic, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $vwanQuery -SubscriptionIds $SubscriptionIds -QueryName "Virtual WANs" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Firewall Policies from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all firewall policy resources containing rule
    collections and configurations for Azure Firewalls. Includes threat intelligence mode,
    DNS settings, intrusion detection, and TLS inspection settings.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for firewall policies.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of firewall policy objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, threatIntelMode, dnsSettings, intrusionDetection, tlsSettings,
    basePolicy, childPolicies, firewalls, provisioningState, tags.

.EXAMPLE
    $fwpolicies = Get-FirewallPolicies -SubscriptionIds @("sub1-guid")
    Retrieves all firewall policies from specified subscription.

.EXAMPLE
    $fwpolicies = Get-FirewallPolicies -SubscriptionIds $subs -PageSize 500
    Retrieves firewall policies with custom page size.

.NOTES
    Contains firewall rules, threat intelligence settings, and security configurations.
    Can be inherited in parent-child policy hierarchies.
#>
function Get-FirewallPolicies {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $fwpQuery = @"
Resources
| where type =~ 'microsoft.network/firewallpolicies'
| extend sku = properties.sku.tier
| extend threatIntelMode = properties.threatIntelMode
| extend dnsSettings = properties.dnsSettings
| extend intrusionDetection = properties.intrusionDetection
| extend tlsSettings = properties.transportSecurity
| extend basePolicy = properties.basePolicy.id
| extend childPolicies = properties.childPolicies
| extend firewalls = properties.firewalls
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, sku, threatIntelMode, dnsSettings, intrusionDetection, tlsSettings, basePolicy, childPolicies, firewalls, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $fwpQuery -SubscriptionIds $SubscriptionIds -QueryName "Firewall Policies" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Application Security Groups from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all application security group resources used
    for grouping VMs and NICs in NSG rules. Essential for resolving NSG rules that reference
    ASGs instead of IP addresses.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for application security groups.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of application security group objects with properties: id, subscriptionId,
    resourceGroup, name, location, provisioningState, tags.

.EXAMPLE
    $asgs = Get-ApplicationSecurityGroups -SubscriptionIds @("sub1-guid")
    Retrieves all application security groups from specified subscription.

.EXAMPLE
    $asgs = Get-ApplicationSecurityGroups -SubscriptionIds $subs -PageSize 500
    Retrieves application security groups with custom page size.

.NOTES
    Used in NSG rules as source or destination instead of IP addresses.
    Enables application-centric network security policies.
#>
function Get-ApplicationSecurityGroups {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $asgQuery = @"
Resources
| where type =~ 'microsoft.network/applicationsecuritygroups'
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $asgQuery -SubscriptionIds $SubscriptionIds -QueryName "Application Security Groups" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure API Management instances with VNet integration from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all API Management instances that are deployed
    with VNet integration (External or Internal mode). Excludes instances without VNet integration.
    Includes SKU details, network configuration, subnet associations, IP addresses, and provisioning state.
    Essential for mapping API gateway infrastructure and network traffic flow.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for API Management instances.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of API Management instance objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, virtualNetworkType, subnetResourceId, publicIpAddresses, privateIpAddresses,
    publicNetworkAccess, provisioningState, tags.

.EXAMPLE
    $apimInstances = Get-APIManagementServices -SubscriptionIds @("sub1-guid")
    Retrieves all VNet-integrated API Management instances from specified subscription.

.EXAMPLE
    $apimInstances = Get-APIManagementServices -SubscriptionIds $subs -PageSize 500
    Retrieves API Management instances with custom page size.

.NOTES
    Only includes instances with VNet integration (External or Internal mode).
    Excludes instances without VNet integration as they have no network topology impact.
    Shows subnet associations and IP addressing for network mapping.
#>
function Get-APIManagementServices {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $apimQuery = @"
Resources
| where type =~ 'microsoft.apimanagement/service'
| extend sku = properties.sku.name
| extend capacity = properties.sku.capacity
| extend virtualNetworkType = properties.virtualNetworkType
| extend subnetResourceId = properties.virtualNetworkConfiguration.subnetResourceId
| extend publicIpAddresses = properties.publicIPAddresses
| extend privateIpAddresses = properties.privateIPAddresses
| extend publicNetworkAccess = properties.publicNetworkAccess
| extend provisioningState = properties.provisioningState
| where virtualNetworkType in~ ('External', 'Internal')
| project id, subscriptionId, resourceGroup, name, location, sku, capacity, virtualNetworkType, subnetResourceId, publicIpAddresses, privateIpAddresses, publicNetworkAccess, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $apimQuery -SubscriptionIds $SubscriptionIds -QueryName "API Management Services" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Traffic Manager profiles from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all Traffic Manager profiles including DNS-based
    routing configuration, traffic routing methods, endpoint details, monitoring configuration,
    and endpoint health status. Essential for mapping global DNS-based load balancing and
    multi-region traffic distribution.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for Traffic Manager profiles.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Traffic Manager profile objects with properties: id, subscriptionId, resourceGroup,
    name, location, trafficRoutingMethod, dnsConfig, monitorConfig, endpoints, endpointCount,
    profileStatus, provisioningState, tags.

.EXAMPLE
    $tmProfiles = Get-TrafficManagerProfiles -SubscriptionIds @("sub1-guid")
    Retrieves all Traffic Manager profiles from specified subscription.

.EXAMPLE
    $tmProfiles = Get-TrafficManagerProfiles -SubscriptionIds $subs -PageSize 500
    Retrieves Traffic Manager profiles with custom page size.

.NOTES
    Shows DNS-based routing configuration and endpoint health monitoring.
    Critical for understanding global traffic distribution and failover strategies.
    Includes all routing methods: Performance, Priority, Weighted, Geographic, MultiValue, Subnet.
#>
function Get-TrafficManagerProfiles {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $tmQuery = @"
Resources
| where type =~ 'microsoft.network/trafficmanagerprofiles'
| extend trafficRoutingMethod = properties.trafficRoutingMethod
| extend dnsConfig = properties.dnsConfig
| extend monitorConfig = properties.monitorConfig
| extend endpoints = properties.endpoints
| extend endpointCount = array_length(properties.endpoints)
| extend profileStatus = properties.profileStatus
| extend provisioningState = properties.provisioningState
| project id, subscriptionId, resourceGroup, name, location, trafficRoutingMethod, dnsConfig, monitorConfig, endpoints, endpointCount, profileStatus, provisioningState, tags
"@

    return Invoke-AzResourceGraphWithPagination -Query $tmQuery -SubscriptionIds $SubscriptionIds -QueryName "Traffic Manager Profiles" -PageSize $PageSize
}

<#
.SYNOPSIS
    Retrieves all Azure Front Door profiles from specified subscriptions.

.DESCRIPTION
    Queries Azure Resource Graph to retrieve all Azure Front Door profiles including both
    Classic (microsoft.network/frontdoors) and Standard/Premium tiers (microsoft.cdn/profiles).
    Includes frontend endpoints, backend pools, routing rules, WAF policies, and enabled state.
    Essential for mapping global HTTP/HTTPS routing, CDN, and application delivery infrastructure.

.PARAMETER SubscriptionIds
    Array of Azure subscription IDs to query for Front Door profiles.

.PARAMETER PageSize
    Number of records to retrieve per page. Default is 1000.

.OUTPUTS
    System.Array
    Returns array of Front Door profile objects with properties: id, subscriptionId, resourceGroup,
    name, location, sku, tier, kind, frontendEndpoints, backendPools, routingRules, wafPolicy,
    enabledState, provisioningState, tags.

.EXAMPLE
    $frontDoors = Get-FrontDoorProfiles -SubscriptionIds @("sub1-guid")
    Retrieves all Front Door profiles from specified subscription.

.EXAMPLE
    $frontDoors = Get-FrontDoorProfiles -SubscriptionIds $subs -PageSize 500
    Retrieves Front Door profiles with custom page size.

.NOTES
    Collects both Classic Front Door and Standard/Premium tiers.
    Shows global routing configuration and WAF security policies.
    Critical for understanding application delivery and global load balancing.
    Standard/Premium use microsoft.cdn/profiles with kind='frontdoor'.
#>
function Get-FrontDoorProfiles {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 1000
    )

    $frontDoorQuery = "Resources | where (type =~ 'microsoft.network/frontdoors') or (type =~ 'microsoft.cdn/profiles' and (tostring(properties.sku.name) =~ 'Standard_AzureFrontDoor' or tostring(properties.sku.name) =~ 'Premium_AzureFrontDoor')) | extend sku = tostring(properties.sku.name) | extend tier = tostring(properties.sku.tier) | extend frontDoorType = iff(type =~ 'microsoft.cdn/profiles', 'frontdoor-premium-standard', 'frontdoor-classic') | extend enabledState = iff(type =~ 'microsoft.network/frontdoors', tostring(properties.enabledState), tostring(properties.resourceState)) | extend provisioningState = tostring(properties.provisioningState) | project id, subscriptionId, resourceGroup, name, location, type, sku, tier, frontDoorType, enabledState, provisioningState, properties, tags"

    return Invoke-AzResourceGraphWithPagination -Query $frontDoorQuery -SubscriptionIds $SubscriptionIds -QueryName "Front Door Profiles" -PageSize $PageSize
}

Export-ModuleMember -Function Invoke-WithRetry, Invoke-AzResourceGraphWithPagination, Get-VirtualNetworks, Get-PrivateDNSZones, Get-PrivateEndpoints, Get-VNetLinks, Get-NetworkSecurityGroups, Get-RouteTables, Get-VPNGateways, Get-ExpressRouteCircuits, Get-AzureFirewalls, Get-ApplicationGateways, Get-LoadBalancers, Get-PublicIPAddresses, Get-BastionHosts, Get-PrivateLinkServices, Get-NATGateways, Get-DDoSProtectionPlans, Get-DNSResolvers, Get-NetworkWatchers, Get-VirtualNetworkGateways, Get-Connections, Get-LocalNetworkGateways, Get-NetworkInterfaces, Get-VirtualHubs, Get-VirtualWANs, Get-FirewallPolicies, Get-ApplicationSecurityGroups, Get-APIManagementServices, Get-TrafficManagerProfiles, Get-FrontDoorProfiles
