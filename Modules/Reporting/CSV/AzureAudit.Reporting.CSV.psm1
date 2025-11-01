Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Export-CSVReports {
    <#
    .SYNOPSIS
    Exports Azure audit results to multiple CSV report files.

    .DESCRIPTION
    The Export-CSVReports function generates structured CSV reports from Azure audit data including virtual networks,
    private DNS zones, private endpoints, and security issues. Each resource type is exported to a separate CSV file
    for simplified data analysis and reporting. The function handles errors gracefully and continues processing
    remaining exports even if individual exports fail.

    .PARAMETER AuditResults
    A hashtable containing the complete audit results from Azure network scanning operations. The hashtable must
    contain keys for VNets, PrivateDNSZones, PrivateEndpoints, and Issues. The Issues property should contain nested
    hashtables with severity levels (Critical, High, Medium, Low, Info) as keys.

    .PARAMETER ReportBasePath
    The base file path for the generated CSV reports. This path will be used as a prefix for all generated files,
    with resource type suffixes appended (e.g., "_VNets.csv", "_PrivateDNSZones.csv"). The directory must exist
    and be writable. Do not include file extensions as they are automatically appended.

    .EXAMPLE
    $auditData = Invoke-AzureNetworkAudit -SubscriptionId "12345678-1234-1234-1234-123456789012"
    $files = Export-CSVReports -AuditResults $auditData -ReportBasePath "C:\Reports\AzureAudit_2025-01-15"

    Exports all audit results to CSV files with the specified base path, returning an array of generated file paths.

    .EXAMPLE
    Export-CSVReports -AuditResults $results -ReportBasePath ".\output\audit" | ForEach-Object { Write-Information $_ -InformationAction Continue }

    Exports CSV reports and displays each generated file path using pipeline processing.

    .OUTPUTS
    System.String[]
    Returns an array of absolute file paths for all successfully generated CSV reports. If a specific export fails,
    that file path will not be included in the output array. The function logs warnings for failed exports.

    .NOTES
    Author: Azure Audit Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later
    Dependencies: Write-AuditLog function must be available in the session

    The function exports the following file types:
    - VNets: Virtual network configurations with address spaces and subnet counts
    - PrivateDNSZones: DNS zone details including record sets and VNet links
    - PrivateEndpoints: Private endpoint configurations and connection states
    - AllIssues: Combined security and compliance issues across all severity levels
    - CriticalIssues: Filtered view of only critical severity issues

    All CSV files are generated with UTF-8 encoding and without type information headers for maximum compatibility
    with data analysis tools. The function uses ErrorAction Stop for individual operations but catches exceptions
    to prevent complete failure if one export type encounters issues.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$ReportBasePath
    )

    Write-AuditLog "Exporting CSV reports..." -Type Info

    $exportedFiles = @()

    try {
        $vnetExport = $AuditResults.VNets | Select-Object @{N='Subscription';E={$_.subscriptionId}},
            @{N='ResourceGroup';E={$_.resourceGroup}},
            @{N='Name';E={$_.name}},
            @{N='Location';E={$_.location}},
            @{N='AddressSpace';E={$_.addressSpace -join ', '}},
            @{N='SubnetCount';E={($_.subnets.Count -as [int]) ?? 0}},
            @{N='PeeringCount';E={($_.peerings.Count -as [int]) ?? 0}},
            @{N='CustomDNS';E={($_.dnsServers -join ', ') ?? 'Azure DNS (168.63.129.16)'}},
            @{N='ProvisioningState';E={$_.provisioningState}}

        $vnetPath = "${ReportBasePath}_VNets.csv"
        $vnetExport | Export-Csv -Path $vnetPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-AuditLog "Exported VNets CSV: $vnetPath" -Type Debug
        $exportedFiles += $vnetPath
    }
    catch {
        Write-AuditLog "Failed to export VNets CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        $dnsZoneExport = $AuditResults.PrivateDNSZones | Select-Object @{N='Subscription';E={$_.subscriptionId}},
            @{N='ResourceGroup';E={$_.resourceGroup}},
            @{N='ZoneName';E={$_.name}},
            @{N='RecordSets';E={$_.numberOfRecordSets}},
            @{N='VNetLinks';E={$_.numberOfVirtualNetworkLinks}},
            @{N='LinksWithRegistration';E={$_.numberOfVirtualNetworkLinksWithRegistration}},
            @{N='ProvisioningState';E={$_.provisioningState}}

        $dnsPath = "${ReportBasePath}_PrivateDNSZones.csv"
        $dnsZoneExport | Export-Csv -Path $dnsPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-AuditLog "Exported DNS Zones CSV: $dnsPath" -Type Debug
        $exportedFiles += $dnsPath
    }
    catch {
        Write-AuditLog "Failed to export DNS Zones CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        $peExport = $AuditResults.PrivateEndpoints | Select-Object @{N='Subscription';E={$_.subscriptionId}},
            @{N='ResourceGroup';E={$_.resourceGroup}},
            @{N='Name';E={$_.name}},
            @{N='Location';E={$_.location}},
            @{N='TargetResource';E={(($_.privateLinkServiceId -split '/')[-1]) ?? 'N/A'}},
            @{N='GroupIds';E={$_.groupIds -join ', '}},
            @{N='ConnectionState';E={$_.connectionState}},
            @{N='ProvisioningState';E={$_.provisioningState}}

        $pePath = "${ReportBasePath}_PrivateEndpoints.csv"
        $peExport | Export-Csv -Path $pePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-AuditLog "Exported Private Endpoints CSV: $pePath" -Type Debug
        $exportedFiles += $pePath
    }
    catch {
        Write-AuditLog "Failed to export Private Endpoints CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        $allIssues = @("Critical", "High", "Medium", "Low", "Info") |
            ForEach-Object { $AuditResults.Issues[$_] } |
            Where-Object { $_ }

        if ($allIssues.Count -gt 0) {
            $allIssuesPath = "${ReportBasePath}_AllIssues.csv"
            $allIssues | Export-Csv -Path $allIssuesPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported All Issues CSV: $allIssuesPath ($($allIssues.Count) issues)" -Type Debug
            $exportedFiles += $allIssuesPath
        }

        if ($AuditResults.Issues.Critical.Count -gt 0) {
            $criticalPath = "${ReportBasePath}_CriticalIssues.csv"
            $AuditResults.Issues.Critical | Export-Csv -Path $criticalPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Critical Issues CSV: $criticalPath ($($AuditResults.Issues.Critical.Count) issues)" -Type Debug
            $exportedFiles += $criticalPath
        }
    }
    catch {
        Write-AuditLog "Failed to export issues CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.VirtualNetworkGateways.Count ?? 0) -gt 0) {
            $vngwExport = $AuditResults.VirtualNetworkGateways | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='GatewayType';E={$_.gatewayType}},
                @{N='VpnType';E={$_.vpnType}},
                @{N='SKU';E={$_.sku}},
                @{N='ActiveActive';E={$_.activeActive}},
                @{N='BGPEnabled';E={$_.enableBgp}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $vngwPath = "${ReportBasePath}_VirtualNetworkGateways.csv"
            $vngwExport | Export-Csv -Path $vngwPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Virtual Network Gateways CSV: $vngwPath" -Type Debug
            $exportedFiles += $vngwPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Virtual Network Gateways CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.Connections.Count ?? 0) -gt 0) {
            $connExport = $AuditResults.Connections | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='ConnectionType';E={$_.connectionType}},
                @{N='GatewayId';E={$_.virtualNetworkGateway1Id}},
                @{N='Peer';E={$_.virtualNetworkGateway2Id ?? $_.localNetworkGateway2Id ?? $_.peerId ?? 'N/A'}},
                @{N='ConnectionStatus';E={$_.connectionStatus}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $connPath = "${ReportBasePath}_Connections.csv"
            $connExport | Export-Csv -Path $connPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Connections CSV: $connPath" -Type Debug
            $exportedFiles += $connPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Connections CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.LocalNetworkGateways.Count ?? 0) -gt 0) {
            $lngwExport = $AuditResults.LocalNetworkGateways | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='GatewayIPAddress';E={$_.gatewayIpAddress}},
                @{N='AddressSpace';E={$_.addressSpace -join ', '}},
                @{N='BGPEnabled';E={$_.bgpEnabled}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $lngwPath = "${ReportBasePath}_LocalNetworkGateways.csv"
            $lngwExport | Export-Csv -Path $lngwPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Local Network Gateways CSV: $lngwPath" -Type Debug
            $exportedFiles += $lngwPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Local Network Gateways CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.NetworkInterfaces.Count ?? 0) -gt 0) {
            $nicExport = $AuditResults.NetworkInterfaces | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='VirtualMachine';E={(($_.virtualMachine -split '/')[-1]) ?? 'N/A'}},
                @{N='PrivateIPAddress';E={$_.privateIPAddress}},
                @{N='SubnetId';E={(($_.subnetId -split '/')[-1]) ?? 'N/A'}},
                @{N='NSGAttached';E={$_.nsgAttached}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $nicPath = "${ReportBasePath}_NetworkInterfaces.csv"
            $nicExport | Export-Csv -Path $nicPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Network Interfaces CSV: $nicPath" -Type Debug
            $exportedFiles += $nicPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Network Interfaces CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.VirtualHubs.Count ?? 0) -gt 0) {
            $vhubExport = $AuditResults.VirtualHubs | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='VirtualWAN';E={(($_.virtualWan -split '/')[-1]) ?? 'N/A'}},
                @{N='AddressPrefix';E={$_.addressPrefix}},
                @{N='RoutingState';E={$_.routingState}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $vhubPath = "${ReportBasePath}_VirtualHubs.csv"
            $vhubExport | Export-Csv -Path $vhubPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Virtual Hubs CSV: $vhubPath" -Type Debug
            $exportedFiles += $vhubPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Virtual Hubs CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.VirtualWANs.Count ?? 0) -gt 0) {
            $vwanExport = $AuditResults.VirtualWANs | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='VirtualWANType';E={$_.virtualWanType}},
                @{N='DisableVpnEncryption';E={$_.disableVpnEncryption}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $vwanPath = "${ReportBasePath}_VirtualWANs.csv"
            $vwanExport | Export-Csv -Path $vwanPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Virtual WANs CSV: $vwanPath" -Type Debug
            $exportedFiles += $vwanPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Virtual WANs CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.FirewallPolicies.Count ?? 0) -gt 0) {
            $fwpExport = $AuditResults.FirewallPolicies | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='ThreatIntelMode';E={$_.threatIntelMode}},
                @{N='RuleCollectionGroups';E={$_.ruleCollectionGroups}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $fwpPath = "${ReportBasePath}_FirewallPolicies.csv"
            $fwpExport | Export-Csv -Path $fwpPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Firewall Policies CSV: $fwpPath" -Type Debug
            $exportedFiles += $fwpPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Firewall Policies CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.ApplicationSecurityGroups.Count ?? 0) -gt 0) {
            $asgExport = $AuditResults.ApplicationSecurityGroups | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $asgPath = "${ReportBasePath}_ApplicationSecurityGroups.csv"
            $asgExport | Export-Csv -Path $asgPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Application Security Groups CSV: $asgPath" -Type Debug
            $exportedFiles += $asgPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Application Security Groups CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.APIManagementServices.Count ?? 0) -gt 0) {
            $apimExport = $AuditResults.APIManagementServices | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='SKU';E={$_.sku}},
                @{N='Capacity';E={$_.capacity}},
                @{N='VirtualNetworkType';E={$_.virtualNetworkType}},
                @{N='SubnetId';E={(($_.subnetResourceId -split '/')[-1]) ?? 'N/A'}},
                @{N='PublicIPAddresses';E={$_.publicIpAddresses -join ', '}},
                @{N='PrivateIPAddresses';E={$_.privateIpAddresses -join ', '}},
                @{N='PublicNetworkAccess';E={$_.publicNetworkAccess}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $apimPath = "${ReportBasePath}_APIManagementServices.csv"
            $apimExport | Export-Csv -Path $apimPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported API Management Services CSV: $apimPath" -Type Debug
            $exportedFiles += $apimPath
        }
    }
    catch {
        Write-AuditLog "Failed to export API Management Services CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.TrafficManagerProfiles.Count ?? 0) -gt 0) {
            $tmExport = $AuditResults.TrafficManagerProfiles | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='TrafficRoutingMethod';E={$_.trafficRoutingMethod}},
                @{N='DNSName';E={$_.dnsConfig.relativeName + '.trafficmanager.net'}},
                @{N='MonitorProtocol';E={$_.monitorConfig.protocol}},
                @{N='MonitorPort';E={$_.monitorConfig.port}},
                @{N='MonitorPath';E={$_.monitorConfig.path}},
                @{N='EndpointCount';E={$_.endpointCount}},
                @{N='ProfileStatus';E={$_.profileStatus}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $tmPath = "${ReportBasePath}_TrafficManagerProfiles.csv"
            $tmExport | Export-Csv -Path $tmPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Traffic Manager Profiles CSV: $tmPath" -Type Debug
            $exportedFiles += $tmPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Traffic Manager Profiles CSV: $($_.Exception.Message)" -Type Warning
    }

    try {
        if (($AuditResults.FrontDoorProfiles.Count ?? 0) -gt 0) {
            $fdExport = $AuditResults.FrontDoorProfiles | Select-Object @{N='Subscription';E={$_.subscriptionId}},
                @{N='ResourceGroup';E={$_.resourceGroup}},
                @{N='Name';E={$_.name}},
                @{N='Location';E={$_.location}},
                @{N='SKU';E={$_.sku}},
                @{N='Tier';E={$_.tier}},
                @{N='Kind';E={$_.kind}},
                @{N='FrontendEndpointCount';E={($_.frontendEndpoints.Count ?? 0)}},
                @{N='BackendPoolCount';E={($_.backendPools.Count ?? 0)}},
                @{N='RoutingRuleCount';E={($_.routingRules.Count ?? 0)}},
                @{N='WAFPolicy';E={if ($_.wafPolicy) { (($_.wafPolicy -split '/')[-1]) } else { 'None' }}},
                @{N='EnabledState';E={$_.enabledState}},
                @{N='ProvisioningState';E={$_.provisioningState}}

            $fdPath = "${ReportBasePath}_FrontDoorProfiles.csv"
            $fdExport | Export-Csv -Path $fdPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-AuditLog "Exported Front Door Profiles CSV: $fdPath" -Type Debug
            $exportedFiles += $fdPath
        }
    }
    catch {
        Write-AuditLog "Failed to export Front Door Profiles CSV: $($_.Exception.Message)" -Type Warning
    }

    Write-AuditLog "CSV exports complete: $($exportedFiles.Count) files" -Type Success
    return $exportedFiles
}

Export-ModuleMember -Function Export-CSVReports
