function Get-MockAuditResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeXSSAttempts,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAllResourceTypes
    )

    $baseResults = @{
        VNets = @(
            @{
                subscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
                resourceGroup = 'mock-rg-networking'
                name = 'vnet-prod-eastus-001'
                location = 'eastus'
                addressSpace = @('10.0.0.0/16', '10.1.0.0/16')
                subnets = @(
                    @{ name = 'subnet-app'; addressPrefix = '10.0.1.0/24' },
                    @{ name = 'subnet-data'; addressPrefix = '10.0.2.0/24' }
                )
                peerings = @(
                    @{ name = 'peering-to-hub'; remoteVirtualNetwork = '/subscriptions/mock-sub/resourceGroups/mock-rg/providers/Microsoft.Network/virtualNetworks/vnet-hub' }
                )
                dnsServers = @('168.63.129.16')
                provisioningState = 'Succeeded'
            }
        )
        PrivateDNSZones = @(
            @{
                subscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
                resourceGroup = 'mock-rg-dns'
                name = 'privatelink.database.windows.net'
                numberOfRecordSets = 15
                numberOfVirtualNetworkLinks = 3
                numberOfVirtualNetworkLinksWithRegistration = 0
                provisioningState = 'Succeeded'
            }
        )
        PrivateEndpoints = @(
            @{
                subscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
                resourceGroup = 'mock-rg-networking'
                name = 'pe-sqlserver-prod'
                location = 'eastus'
                subnetId = '/subscriptions/mock-sub/resourceGroups/mock-rg/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/subnet-data'
                privateLinkServiceId = '/subscriptions/mock-sub/resourceGroups/mock-rg/providers/Microsoft.Sql/servers/sqlserver-prod'
                groupIds = @('sqlServer')
                connectionState = 'Approved'
                provisioningState = 'Succeeded'
            }
        )
        Issues = @{
            Critical = @()
            High = @()
            Medium = @()
            Low = @()
            Info = @()
        }
        Statistics = @{
            TotalVNets = 1
            TotalSubnets = 2
            TotalPrivateDNSZones = 1
            TotalPrivateEndpoints = 1
            TotalVNetLinks = 3
            TotalPeerings = 1
        }
    }

    if ($IncludeXSSAttempts) {
        $baseResults.Issues.Critical += @{
            Timestamp = '2025-01-15T10:30:00Z'
            Category = 'Network Security'
            Title = 'XSS Test: <script>alert("xss")</script> in title'
            Description = 'XSS Test: </script><img src=x onerror=alert(1)> in description'
            ResourceName = 'test-resource-<svg/onload=alert("xss")>'
            ResourceType = 'Microsoft.Network/virtualNetworks'
            SubscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
            Remediation = 'Test remediation with special chars: & < > " '' `'
        }

        $baseResults.Issues.High += @{
            Timestamp = '2025-01-15T10:31:00Z'
            Category = 'Compliance'
            Title = 'JavaScript injection test: javascript:alert(document.cookie)'
            Description = 'Data URI test: data:text/html,<script>alert(1)</script>'
            ResourceName = 'vnet-prod-eastus-001'
            ResourceType = 'Microsoft.Network/virtualNetworks'
            SubscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
            Remediation = 'Review configuration'
        }
    }

    $baseResults.Issues.Medium += @{
        Timestamp = '2025-01-15T10:32:00Z'
        Category = 'Capacity Planning'
        Title = 'High subnet utilization detected'
        Description = 'Subnet subnet-app is 85% utilized (43 of 50 IPs used)'
        ResourceName = 'vnet-prod-eastus-001/subnet-app'
        ResourceType = 'Microsoft.Network/virtualNetworks/subnets'
        SubscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
        Remediation = 'Consider expanding subnet address space or migrating resources'
    }

    $baseResults.Issues.Low += @{
        Timestamp = '2025-01-15T10:33:00Z'
        Category = 'Configuration'
        Title = 'Empty subnet detected'
        Description = 'Subnet subnet-reserved has no resources deployed'
        ResourceName = 'vnet-prod-eastus-001/subnet-reserved'
        ResourceType = 'Microsoft.Network/virtualNetworks/subnets'
        SubscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
        Remediation = 'Consider removing unused subnet or documenting reservation purpose'
    }

    $baseResults.Issues.Info += @{
        Timestamp = '2025-01-15T10:34:00Z'
        Category = 'Information'
        Title = 'IPv6 detected in address space'
        Description = 'Virtual network contains IPv6 address ranges'
        ResourceName = 'vnet-prod-eastus-001'
        ResourceType = 'Microsoft.Network/virtualNetworks'
        SubscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
        Remediation = 'No action required if IPv6 is intentional'
    }

    if ($IncludeAllResourceTypes) {
        $baseResults.VirtualNetworkGateways = @(
            @{
                subscriptionId = 'mock-sub-11111111-1111-1111-1111-111111111111'
                resourceGroup = 'mock-rg-networking'
                name = 'vng-prod-vpn'
                location = 'eastus'
                gatewayType = 'Vpn'
                vpnType = 'RouteBased'
                sku = 'VpnGw2'
                activeActive = $true
                enableBgp = $true
                provisioningState = 'Succeeded'
            }
        )
        $baseResults.Statistics.TotalVirtualNetworkGateways = 1

        $baseResults.Connections = @()
        $baseResults.LocalNetworkGateways = @()
        $baseResults.NetworkInterfaces = @()
        $baseResults.VirtualHubs = @()
        $baseResults.VirtualWANs = @()
        $baseResults.FirewallPolicies = @()
        $baseResults.ApplicationSecurityGroups = @()
        $baseResults.APIManagementServices = @()
        $baseResults.TrafficManagerProfiles = @()
        $baseResults.FrontDoorProfiles = @()
    }

    return $baseResults
}
