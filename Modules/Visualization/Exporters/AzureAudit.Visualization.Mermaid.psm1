Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Constants = @{
    MAX_VNETS_FOR_MARKDOWN_RENDERERS = 50
}

function Export-MermaidDiagram {
    <#
    .SYNOPSIS
        Exports Azure network topology to Mermaid diagram format.

    .DESCRIPTION
        Generates a Mermaid markdown diagram representing Azure network infrastructure.
        Creates a graph visualization showing virtual networks, peerings, and security
        issues. Limits output by default to prevent rendering issues in markdown viewers.
        Color codes nodes based on health status. Output can be rendered at mermaid.live
        or in markdown viewers supporting Mermaid syntax.

    .PARAMETER AuditResults
        Hashtable containing Azure network audit results including VNets, peerings,
        and security issues. Must contain VNets array with peering information.

    .PARAMETER OutputPath
        Full file path where the Mermaid diagram file (.mmd) will be saved.
        File will be written using UTF-8 encoding without BOM.

    .PARAMETER MaxVNets
        Maximum number of VNets to include in diagram. Defaults to 50 for optimal
        rendering performance in markdown viewers. Mermaid.live can handle larger
        diagrams but GitHub/GitLab markdown renderers may timeout above 50 nodes.

    .OUTPUTS
        None. Writes Mermaid diagram file to disk at specified OutputPath.

    .EXAMPLE
        Export-MermaidDiagram -AuditResults $results -OutputPath "C:\Reports\network.mmd"
        Generates Mermaid diagram file for first 50 VNets with peerings.

    .EXAMPLE
        Export-MermaidDiagram -AuditResults $auditData -OutputPath ".\output\diagram.mmd"
        Creates Mermaid diagram file with color-coded network topology.

    .EXAMPLE
        Export-MermaidDiagram -AuditResults $results -OutputPath ".\network.mmd" -MaxVNets 100
        Generates Mermaid diagram with increased VNet limit for viewing in mermaid.live.

    .NOTES
        Encoding: UTF-8 without BOM
        Diagram type: graph TB (top-to-bottom flowchart)
        Rendering limits:
        - GitHub/GitLab markdown: 50 nodes recommended (30-second timeout)
        - Mermaid.live: 500+ nodes supported
        - VS Code Mermaid Preview: 200 nodes recommended
        Color scheme:
        - Blue (#0078D4): Healthy virtual networks
        - Red (#E81123): Virtual networks with critical/high issues
        - Green (#00B294): Private DNS zones
        Node labels include VNet names and address spaces
        Edge types: solid (connected peering), dashed (disconnected peering)
        View online: https://mermaid.live/
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$MaxVNets = $script:Constants.MAX_VNETS_FOR_MARKDOWN_RENDERERS
    )

    try {
        if (-not $AuditResults) {
            throw "AuditResults parameter cannot be null"
        }

        if (-not $AuditResults.ContainsKey('VNets')) {
            throw "AuditResults must contain VNets property"
        }

        Write-AuditLog "Generating Mermaid diagram..." -Type Progress

        $vnetCount = ($AuditResults.VNets?.Count ?? 0)
        if ($vnetCount -eq 0) {
            Write-AuditLog "Warning: No VNets found in audit results" -Type Warning
        }

        if ($vnetCount -gt $MaxVNets) {
            Write-AuditLog "VNet count ($vnetCount) exceeds MaxVNets limit ($MaxVNets), truncating to first $MaxVNets" -Type Warning
            Write-AuditLog "Reason: Mermaid diagrams with >$MaxVNets nodes may timeout in GitHub/GitLab markdown renderers" -Type Info
            Write-AuditLog "To include all VNets, increase -MaxVNets parameter (best viewed in mermaid.live)" -Type Info
        }

    $mermaid = @"
graph TB
    classDef vnetClass fill:#0078D4,stroke:#005a9e,color:#fff
    classDef issueClass fill:#E81123,stroke:#c21e1e,color:#fff
    classDef dnsClass fill:#00B294,stroke:#00907a,color:#fff

"@

        $nodeId = 0
        $nodeMap = @{}

        foreach ($vnet in $AuditResults.VNets | Select-Object -First $MaxVNets) {
            $vnetIssues = ($AuditResults.Issues?.Critical ?? @()) + ($AuditResults.Issues?.High ?? @()) |
                          Where-Object { $_.ResourceName -eq $vnet.name }

            $vnetIssuesCount = @($vnetIssues).Count
            $class = $vnetIssuesCount -gt 0 ? 'issueClass' : 'vnetClass'
            $label = "$($vnet.name)<br/>$($vnet.addressSpace -join '<br/>')"

            $nodeName = "vnet$nodeId"
            $nodeMap[$vnet.id] = $nodeName
            $mermaid += "    $nodeName[`"$label`"]:::$class`n"
            $nodeId++
        }

        $mermaid += "`n"

        foreach ($vnet in $AuditResults.VNets | Select-Object -First $MaxVNets) {
            if ($vnet.peerings) {
                foreach ($peering in $vnet.peerings) {
                    $remoteId = $peering.properties?.remoteVirtualNetwork?.id
                    if ($remoteId -and $nodeMap.ContainsKey($vnet.id) -and $nodeMap.ContainsKey($remoteId)) {
                        $status = $peering.properties.peeringState ?? 'Unknown'
                        $arrow = $status -eq 'Connected' ? '<==>|Peering|' : '-.->'
                        $mermaid += "    $($nodeMap[$vnet.id]) $arrow $($nodeMap[$remoteId])`n"
                    }
                }
            }
        }

        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($OutputPath, $mermaid, $utf8NoBom)

        $fileSizeKB = [Math]::Round((Get-Item $OutputPath).Length / 1KB, 2)
        Write-AuditLog "Mermaid diagram exported to: $OutputPath (${fileSizeKB}KB, $nodeId nodes)" -Type Success
        Write-AuditLog "View online: https://mermaid.live/" -Type Info
    }
    catch {
        Write-AuditLog "Failed to generate Mermaid diagram: $($_.Exception.Message)" -Type Error
        throw
    }
}

Export-ModuleMember -Function Export-MermaidDiagram
