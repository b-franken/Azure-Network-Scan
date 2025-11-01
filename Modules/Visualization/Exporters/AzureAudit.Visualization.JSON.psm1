Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Export-NetworkGraphJSON {
    <#
    .SYNOPSIS
        Exports Azure network topology audit results to NetJSON format.

    .DESCRIPTION
        Exports Azure network infrastructure data to NetJSON format, a standard network
        graph representation. Creates a comprehensive network topology document including
        virtual networks, peerings, private endpoints, private DNS zones, and their
        interconnections. Includes metadata, statistics, and security issues.

    .PARAMETER AuditResults
        Hashtable containing Azure network audit results including VNets, subnets,
        peerings, private DNS zones, private endpoints, VNet links, statistics, and
        identified security issues. Must contain VNets array and Statistics object.

    .PARAMETER OutputPath
        Full file path where the NetJSON file will be saved. File will be written
        using UTF-8 encoding without BOM for maximum compatibility.

    .OUTPUTS
        None. Writes NetJSON file to disk at specified OutputPath.

    .EXAMPLE
        Export-NetworkGraphJSON -AuditResults $results -OutputPath "C:\Reports\network.json"
        Exports network topology to JSON file with all nodes, links, and metadata.

    .EXAMPLE
        Export-NetworkGraphJSON -AuditResults $auditData -OutputPath ".\output\topology.json"
        Exports network data to relative path with complete graph structure.

    .NOTES
        File format: NetJSON protocol version 1.0
        Encoding: UTF-8 without BOM
        Graph includes: VNets, private endpoints, DNS zones, peerings, DNS links, issues
        Nodes contain full Azure resource properties and associated security issues
        Links represent peerings, private endpoint connections, and DNS zone links
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        if (-not $AuditResults) {
            throw "AuditResults parameter cannot be null"
        }

        if (-not $AuditResults.ContainsKey('VNets')) {
            throw "AuditResults must contain VNets property"
        }

        if (-not $AuditResults.ContainsKey('Statistics')) {
            throw "AuditResults must contain Statistics property"
        }

        Write-AuditLog "Generating NetJSON network graph..." -Type Progress

        $vnetCount = ($AuditResults.VNets?.Count ?? 0)
        if ($vnetCount -eq 0) {
            Write-AuditLog "Warning: No VNets found in audit results" -Type Warning
        }

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Building graph structure" -PercentComplete 10

        $graph = @{
        type = "NetworkGraph"
        protocol = "NetJSON"
        version = "1.0"
        label = "Azure Network Topology"
        generated = (Get-Date).ToString("o")
        metadata = @{
            subscriptions = $AuditResults.Statistics.TotalSubscriptions
            vnets = $AuditResults.Statistics.TotalVNets
            subnets = $AuditResults.Statistics.TotalSubnets
            privateDNSZones = $AuditResults.Statistics.TotalPrivateDNSZones
            privateEndpoints = $AuditResults.Statistics.TotalPrivateEndpoints
            peerings = $AuditResults.Statistics.TotalPeerings
            issues = @{
                critical = $AuditResults.Issues.Critical.Count
                high = $AuditResults.Issues.High.Count
                medium = $AuditResults.Issues.Medium.Count
            }
        }
        nodes = @()
        links = @()
    }

        $nodeIndex = @{}
        $nodeId = 0

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Processing VNets" -PercentComplete 20

        foreach ($vnet in $AuditResults.VNets) {
        $vnetIssues = $AuditResults.Issues.Critical + $AuditResults.Issues.High +
                      $AuditResults.Issues.Medium |
                      Where-Object { $_.ResourceName -eq $vnet.name }

        $node = @{
            id = "vnet-$nodeId"
            label = $vnet.name
            type = "virtualNetwork"
            properties = @{
                azureId = $vnet.id
                addressSpace = $vnet.addressSpace
                location = $vnet.location
                subscriptionId = $vnet.subscriptionId
                resourceGroup = $vnet.resourceGroup
                provisioningState = $vnet.provisioningState
                dnsServers = $vnet.dnsServers
            }
            issues = @($vnetIssues | ForEach-Object {
                @{
                    severity = $_.Severity
                    title = $_.Title
                    category = $_.Category
                }
            })
        }

        $graph.nodes += $node
        $nodeIndex[$vnet.id] = "vnet-$nodeId"
        $nodeId++
    }

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Processing VNet peerings" -PercentComplete 40

        foreach ($vnet in $AuditResults.VNets) {
            if ($vnet.peerings) {
                foreach ($peering in $vnet.peerings) {
                if ($nodeIndex.ContainsKey($vnet.id) -and $nodeIndex.ContainsKey($peering.remoteVirtualNetwork.id)) {
                    $link = @{
                        source = $nodeIndex[$vnet.id]
                        target = $nodeIndex[$peering.remoteVirtualNetwork.id]
                        type = "peering"
                        properties = @{
                            name = $peering.name
                            peeringState = $peering.peeringState
                            allowVirtualNetworkAccess = $peering.allowVirtualNetworkAccess
                            allowForwardedTraffic = $peering.allowForwardedTraffic
                            allowGatewayTransit = $peering.allowGatewayTransit
                            useRemoteGateways = $peering.useRemoteGateways
                        }
                    }
                    $graph.links += $link
                }
            }
        }
    }

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Processing private endpoints" -PercentComplete 60

        foreach ($pe in ($AuditResults.PrivateEndpoints ?? @())) {
        $vnetId = ($pe.subnet.id -split "/subnets/")[0]
        if ($nodeIndex.ContainsKey($vnetId)) {
            $node = @{
                id = "pe-$nodeId"
                label = $pe.name
                type = "privateEndpoint"
                properties = @{
                    azureId = $pe.id
                    location = $pe.location
                    subscriptionId = $pe.subscriptionId
                    resourceGroup = $pe.resourceGroup
                    privateLinkServiceId = $pe.privateLinkServiceId
                    groupIds = $pe.groupIds
                    privateIPAddress = ($pe.networkInterfaces[0].ipConfigurations[0].privateIPAddress ?? "N/A")
                    connectionState = ($pe.privateLinkServiceConnections[0].privateLinkServiceConnectionState.status ?? "Unknown")
                }
            }

            $graph.nodes += $node

            $link = @{
                source = $nodeIndex[$vnetId]
                target = "pe-$nodeId"
                type = "privateEndpointConnection"
            }
            $graph.links += $link

            $nodeId++
        }
    }

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Processing DNS zones" -PercentComplete 80

        foreach ($dnsZone in ($AuditResults.PrivateDNSZones ?? @())) {
            $linkedVNets = ($AuditResults.VNetLinks ?? @()) | Where-Object { $_.privateDnsZoneId -eq $dnsZone.id }

        $node = @{
            id = "dns-$nodeId"
            label = $dnsZone.name
            type = "privateDNSZone"
            properties = @{
                azureId = $dnsZone.id
                subscriptionId = $dnsZone.subscriptionId
                resourceGroup = $dnsZone.resourceGroup
                recordCount = ($dnsZone.numberOfRecordSets ?? 0)
                linkedVNetsCount = (@($linkedVNets).Count)
            }
        }

        $graph.nodes += $node

        foreach ($link in $linkedVNets) {
            $vnetId = $link.virtualNetworkId
            if ($nodeIndex.ContainsKey($vnetId)) {
                $dnsLink = @{
                    source = "dns-$nodeId"
                    target = $nodeIndex[$vnetId]
                    type = "dnsZoneLink"
                    properties = @{
                        registrationEnabled = ($link.registrationEnabled ?? $false)
                    }
                }
                $graph.links += $dnsLink
            }
        }

            $nodeId++
        }

        Write-Progress -Activity "Generating JSON Network Graph" -Status "Serializing to JSON" -PercentComplete 90

        $jsonContent = $graph | ConvertTo-Json -Depth 10 -EscapeHandling EscapeHtml
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($OutputPath, $jsonContent, $utf8NoBom)

        Write-Progress -Activity "Generating JSON Network Graph" -Completed

        $fileSizeKB = [Math]::Round((Get-Item $OutputPath).Length / 1KB, 2)
        Write-AuditLog "Network graph JSON exported to: $OutputPath (${fileSizeKB}KB)" -Type Success
    }
    catch {
        Write-AuditLog "Failed to generate JSON network graph: $($_.Exception.Message)" -Type Error
        throw
    }
}

Export-ModuleMember -Function Export-NetworkGraphJSON
