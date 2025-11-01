Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Export-DrawIOCSV {
    <#
    .SYNOPSIS
        Exports Azure network topology to Draw.io compatible CSV format.

    .DESCRIPTION
        Generates a CSV file formatted for import into Draw.io (diagrams.net). Creates
        two sections: nodes and connections. Nodes include virtual networks and private
        DNS zones with properties. Connections represent peerings and DNS zone links.
        Output can be imported via Arrange > Insert > Advanced > CSV in Draw.io.

    .PARAMETER AuditResults
        Hashtable containing Azure network audit results including VNets, private DNS zones,
        peerings, and VNet links. Must contain VNets and PrivateDNSZones arrays.

    .PARAMETER OutputPath
        Full file path where the Draw.io CSV file will be saved. File will be written
        using UTF-8 encoding without BOM for maximum compatibility with Draw.io.

    .OUTPUTS
        None. Writes CSV file to disk at specified OutputPath.

    .EXAMPLE
        Export-DrawIOCSV -AuditResults $results -OutputPath "C:\Reports\network.csv"
        Generates Draw.io CSV file with all VNets, DNS zones, and connections.

    .EXAMPLE
        Export-DrawIOCSV -AuditResults $auditData -OutputPath ".\output\diagram.csv"
        Creates CSV file ready for import into Draw.io.

    .NOTES
        Encoding: UTF-8 without BOM
        CSV format: Draw.io Advanced CSV Import compatible
        Sections:
        - Nodes: id, label, type, addressSpace, location, subscription, hasIssues
        - Connections: source, target, relation, status
        Node types: VirtualNetwork, PrivateDNSZone
        Connection types: Peering, DNSLink
        Import in Draw.io: Arrange > Insert > Advanced > CSV...
        Issue flagging: Critical and High severity issues marked as "Yes"
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    Write-AuditLog "Generating Draw.io CSV..." -Type Progress

    $csv = @()
    $csv += "## Nodes"
    $csv += "id,label,type,addressSpace,location,subscription,hasIssues"

    foreach ($vnet in $AuditResults.VNets) {
        $vnetIssues = $AuditResults.Issues.Critical + $AuditResults.Issues.High |
                      Where-Object { $_.ResourceName -eq $vnet.name }

        $vnetIssuesCount = @($vnetIssues).Count
        $addressSpace = $vnet.addressSpace -join '; '
        $hasIssues = $vnetIssuesCount -gt 0 ? 'Yes' : 'No'

        $csv += "$($vnet.id),`"$($vnet.name)`",VirtualNetwork,`"$addressSpace`",$($vnet.location),$($vnet.subscriptionId),$hasIssues"
    }

    foreach ($zone in $AuditResults.PrivateDNSZones) {
        $csv += "$($zone.id),`"$($zone.name)`",PrivateDNSZone,,$($zone.resourceGroup),$($zone.subscriptionId),No"
    }

    $csv += ""
    $csv += "## Connections"
    $csv += "source,target,relation,status"

    foreach ($vnet in $AuditResults.VNets) {
        if ($vnet.peerings) {
            foreach ($peering in $vnet.peerings) {
                $remoteId = $peering.properties.remoteVirtualNetwork.id
                $status = $peering.properties.peeringState
                $csv += "$($vnet.id),$remoteId,Peering,$status"
            }
        }
    }

    foreach ($link in $AuditResults.VNetLinks) {
        $dnsZoneId = "/subscriptions/$($link.subscriptionId)/resourceGroups/$($link.resourceGroup)/providers/Microsoft.Network/privateDnsZones/$($link.zoneName)"
        $csv += "$($link.vnetId),$dnsZoneId,DNSLink,$($link.linkState)"
    }

    $csvContent = $csv -join "`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($OutputPath, $csvContent, $utf8NoBom)
    Write-AuditLog "Draw.io CSV exported to: $OutputPath" -Type Success
    Write-AuditLog "Import in Draw.io: Arrange > Insert > Advanced > CSV..." -Type Info
}

Export-ModuleMember -Function Export-DrawIOCSV
