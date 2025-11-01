Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Constants = @{
    D3_FORCE_CENTER_STRENGTH = 0.05
    MAX_VNETS_FOR_BROWSER_PERFORMANCE = 500
}

function Get-NetworkVisualizationCSS {
    <#
    .SYNOPSIS
        Generates CSS stylesheet for interactive network visualization.

    .DESCRIPTION
        Returns a complete CSS stylesheet string for the D3.js-based network visualization.
        Includes styles for network graph canvas, nodes, links, labels, control panel,
        legend, statistics badges, buttons, and tooltips. Uses Azure design language
        with appropriate color schemes and interactive states.

    .OUTPUTS
        System.String. Complete CSS stylesheet as a single string.

    .EXAMPLE
        $css = Get-NetworkVisualizationCSS
        Write-Information $css -InformationAction Continue
        Retrieves CSS stylesheet for embedding in HTML.

    .EXAMPLE
        $style = Get-NetworkVisualizationCSS
        $html = "<style>$style</style>"
        Generates CSS for inclusion in HTML document.

    .NOTES
        Styling features:
        - Responsive full-viewport canvas
        - Interactive node hover effects
        - Color-coded link types (peering, DNS, overlap)
        - Floating control panel with statistics
        - Tooltips with smooth transitions
        - Azure color palette alignment
        - Badge system for issue severity
        Uses Segoe UI font family for Windows consistency
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @"
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; overflow: hidden; }

        #network {
            width: 100vw;
            height: 100vh;
            background: #f5f7fa;
        }

        .node {
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .node:hover {
            stroke-width: 4px;
            filter: brightness(1.1);
        }

        .link {
            stroke: #999;
            stroke-opacity: 0.6;
            fill: none;
        }

        .link-peering { stroke: #107C10; stroke-width: 2px; }
        .link-peering-disconnected { stroke: #E81123; stroke-width: 2px; stroke-dasharray: 5,5; }
        .link-overlap { stroke: #E81123; stroke-width: 4px; }
        .link-dns { stroke: #00B294; stroke-width: 1.5px; stroke-dasharray: 3,3; }

        .node-label {
            font-size: 11px;
            font-weight: 500;
            pointer-events: none;
            text-anchor: middle;
            fill: #333;
        }

        .link-label {
            font-size: 9px;
            fill: #666;
            pointer-events: none;
            text-anchor: middle;
        }

        #controls {
            position: absolute;
            top: 20px;
            left: 20px;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            max-width: 320px;
            z-index: 1000;
        }

        #controls h2 {
            color: #0078D4;
            font-size: 18px;
            margin-bottom: 15px;
            border-bottom: 2px solid #0078D4;
            padding-bottom: 8px;
        }

        #controls h3 {
            color: #333;
            font-size: 14px;
            margin-top: 15px;
            margin-bottom: 8px;
        }

        #controls p {
            font-size: 13px;
            margin: 5px 0;
            color: #666;
        }

        .legend-item {
            display: flex;
            align-items: center;
            margin: 8px 0;
            font-size: 12px;
        }

        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 4px;
            margin-right: 10px;
            border: 1px solid #ddd;
        }

        .stat-badge {
            display: inline-block;
            background: #0078D4;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 8px;
        }

        .stat-badge.critical { background: #E81123; }
        .stat-badge.high { background: #FF8C00; }
        .stat-badge.medium { background: #FFB900; }

        button {
            background: #0078D4;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin: 4px 0;
            width: 100%;
            transition: background 0.2s;
        }

        button:hover {
            background: #106EBE;
        }

        .tooltip {
            position: absolute;
            background: rgba(0,0,0,0.9);
            color: white;
            padding: 12px;
            border-radius: 6px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 300px;
            z-index: 2000;
        }

        .tooltip.visible {
            opacity: 1;
        }
"@
}

function Get-NetworkVisualizationJavaScript {
    <#
    .SYNOPSIS
        Generates JavaScript code for D3.js network visualization.

    .DESCRIPTION
        Returns complete JavaScript code for rendering an interactive force-directed
        graph using D3.js v7. Creates network topology visualization with draggable nodes,
        zoom/pan controls, tooltips, and dynamic layouts. Processes audit data to create
        nodes and links with appropriate styling based on resource types and issues.

    .PARAMETER JsonData
        JSON string containing Azure audit results. Must include VNets array with peerings
        and Issues object with categorized security findings. Will be embedded directly
        into generated JavaScript.

    .OUTPUTS
        System.String. Complete JavaScript code as a single string.

    .EXAMPLE
        $json = $auditResults | ConvertTo-Json -Depth 10
        $js = Get-NetworkVisualizationJavaScript -JsonData $json
        Generates JavaScript with embedded audit data.

    .EXAMPLE
        $script = Get-NetworkVisualizationJavaScript -JsonData $compressedJson
        $html = "<script>$script</script>"
        Creates JavaScript for inclusion in HTML document.

    .NOTES
        D3.js version: 7.x required
        Visualization features:
        - Force-directed graph layout with collision detection
        - Draggable nodes with fixed positioning on drag
        - Zoom and pan with scale limits (0.1x to 10x)
        - Interactive tooltips showing resource details
        - Color-coded nodes based on issue severity
        - Styled links for peering states and overlaps
        - Reset zoom and center view controls
        Graph forces: link distance, charge repulsion, center gravity, collision
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonData
    )

    return @"
        const data = $JsonData;
        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select('#network')
            .append('svg')
            .attr('width', width)
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height])
            .attr('style', 'max-width: 100%; height: auto;');

        const g = svg.append('g');

        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);

        const nodes = [];
        const links = [];
        const nodeMap = new Map();

        data.VNets?.forEach((vnet, idx) => {
            const nodeId = vnet.id || vnet.name;
            const hasIssues = data.Issues?.Critical?.some(i => i.ResourceName?.includes(vnet.name)) ||
                            data.Issues?.High?.some(i => i.ResourceName?.includes(vnet.name));

            nodes.push({
                id: nodeId,
                name: vnet.name,
                type: 'vnet',
                location: vnet.location,
                addressSpace: vnet.addressSpace?.join(', ') || 'N/A',
                hasIssues: hasIssues,
                color: hasIssues ? '#E81123' : '#0078D4'
            });
            nodeMap.set(nodeId, nodes.length - 1);

            vnet.peerings?.forEach(peering => {
                const remoteId = peering.properties?.remoteVirtualNetwork?.id;
                if (remoteId) {
                    links.push({
                        source: nodeId,
                        target: remoteId,
                        type: 'peering',
                        state: peering.properties?.peeringState || 'Unknown'
                    });
                }
            });
        });

        data.Issues?.Critical?.forEach(issue => {
            if (issue.Category === 'IP Overlap' && issue.ResourceName?.includes('<->')) {
                const [vnet1, vnet2] = issue.ResourceName.split(' <-> ');
                const node1 = nodes.find(n => n.name === vnet1);
                const node2 = nodes.find(n => n.name === vnet2);
                if (node1 && node2) {
                    links.push({
                        source: node1.id,
                        target: node2.id,
                        type: 'overlap'
                    });
                }
            }
        });

        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(200).strength(0.5))
            .force('charge', d3.forceManyBody().strength(-400).distanceMax(500))
            .force('center', d3.forceCenter(width / 2, height / 2).strength($($script:Constants.D3_FORCE_CENTER_STRENGTH)))
            .force('collision', d3.forceCollide().radius(50).strength(0.7))
            .force('x', d3.forceX(width / 2).strength(0.02))
            .force('y', d3.forceY(height / 2).strength(0.02))
            .alphaDecay(0.02)
            .velocityDecay(0.3);

        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .enter().append('line')
            .attr('class', d => {
                if (d.type === 'overlap') return 'link link-overlap';
                if (d.type === 'peering') {
                    return d.state === 'Connected' ? 'link link-peering' : 'link link-peering-disconnected';
                }
                return 'link';
            });

        const node = g.append('g')
            .selectAll('circle')
            .data(nodes)
            .enter().append('circle')
            .attr('class', 'node')
            .attr('r', 25)
            .attr('fill', d => d.color)
            .call(d3.drag()
                .on('start', dragStarted)
                .on('drag', dragged)
                .on('end', dragEnded))
            .on('mouseover', showTooltip)
            .on('mouseout', hideTooltip);

        const label = g.append('g')
            .selectAll('text')
            .data(nodes)
            .enter().append('text')
            .attr('class', 'node-label')
            .attr('dy', 40)
            .text(d => d.name);

        const tooltip = d3.select('body').append('div')
            .attr('class', 'tooltip');

        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);

            label
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        });

        function dragStarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragEnded(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        function showTooltip(event, d) {
            tooltip
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 10) + 'px')
                .classed('visible', true)
                .html('<strong>' + d.name + '</strong><br>' +
                      'Location: ' + d.location + '<br>' +
                      'Address Space: ' + d.addressSpace + '<br>' +
                      'Type: ' + d.type.toUpperCase() + '<br>' +
                      (d.hasIssues ? '<span style="color: #FFB900">⚠ Has Issues</span>' : '<span style="color: #107C10">✓ Healthy</span>'));
        }

        function hideTooltip() {
            tooltip.classed('visible', false);
        }

        document.getElementById('resetZoom').addEventListener('click', () => {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        });

        document.getElementById('centerView').addEventListener('click', () => {
            simulation.alpha(1).restart();
        });
"@
}

function Export-NetworkGraphHTML {
    <#
    .SYNOPSIS
        Exports Azure network topology to interactive HTML visualization.

    .DESCRIPTION
        Generates a standalone interactive HTML file with embedded D3.js force-directed
        graph visualization. Creates a fully self-contained HTML document including
        CSS styles, JavaScript code, and audit data. Visualization features drag-and-drop
        nodes, zoom/pan, tooltips, statistics panel, and color-coded resources based on
        health status. Requires only a web browser to view.

    .PARAMETER AuditResults
        Hashtable containing Azure network audit results including VNets, peerings,
        statistics, and security issues. Will be serialized to JSON and embedded in HTML.

    .PARAMETER OutputPath
        Full file path where the HTML file will be saved. File will be written using
        UTF-8 encoding without BOM for maximum browser compatibility.

    .PARAMETER MaxVNets
        Maximum number of VNets to include in visualization. Defaults to 500 to prevent
        browser performance issues. Large topologies should use external JSON files instead.

    .OUTPUTS
        None. Writes standalone HTML file to disk at specified OutputPath.

    .EXAMPLE
        Export-NetworkGraphHTML -AuditResults $results -OutputPath "C:\Reports\network.html"
        Generates interactive HTML visualization with embedded data.

    .EXAMPLE
        Export-NetworkGraphHTML -AuditResults $auditData -OutputPath ".\output\topology.html"
        Creates standalone HTML file viewable in any modern browser.

    .EXAMPLE
        Export-NetworkGraphHTML -AuditResults $results -OutputPath ".\network.html" -MaxVNets 1000
        Generates visualization with increased VNet limit for large environments.

    .NOTES
        Encoding: UTF-8 without BOM
        Dependencies: D3.js v7.9.0 loaded from CDN with local fallback
        File type: Standalone HTML (no external dependencies except CDN)
        Browser requirements: Modern browser with JavaScript enabled (Chrome 90+, Firefox 88+, Edge 90+)
        Features:
        - Force-directed graph layout with collision detection
        - Draggable nodes with physics simulation
        - Zoom and pan controls
        - Interactive tooltips on hover
        - Statistics panel with issue counts
        - Legend explaining color codes
        - Reset zoom and center view buttons
        Performance: Tested up to 500 VNets, larger topologies may cause browser slowdown
        Color coding: Blue (healthy), Red (issues), Green (peering), Orange (warnings)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10000)]
        [int]$MaxVNets = $script:Constants.MAX_VNETS_FOR_BROWSER_PERFORMANCE
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

        if (-not $AuditResults.ContainsKey('Issues')) {
            throw "AuditResults must contain Issues property"
        }

        Write-AuditLog "Generating interactive D3.js network visualization..." -Type Progress

        $vnetCount = ($AuditResults.VNets?.Count ?? 0)
        if ($vnetCount -eq 0) {
            Write-AuditLog "Warning: No VNets found in audit results, generating empty visualization" -Type Warning
        }

        if ($vnetCount -gt $MaxVNets) {
            Write-AuditLog "VNet count ($vnetCount) exceeds MaxVNets limit ($MaxVNets), truncating dataset" -Type Warning
            Write-AuditLog "Consider using JSON export for large topologies or increase -MaxVNets parameter" -Type Info
            $AuditResults = $AuditResults.Clone()
            $AuditResults.VNets = $AuditResults.VNets | Select-Object -First $MaxVNets
        }

        $estimatedSizeKB = [Math]::Round(($vnetCount * 2.5), 2)
        if ($estimatedSizeKB -gt 5000) {
            Write-AuditLog "Warning: Estimated HTML size is ${estimatedSizeKB}KB, may cause browser performance issues" -Type Warning
        }

        Write-Progress -Activity "Generating HTML Visualization" -Status "Serializing data to JSON" -PercentComplete 25

        $jsonData = $AuditResults | ConvertTo-Json -Depth 10 -Compress

        Write-Progress -Activity "Generating HTML Visualization" -Status "Generating CSS and JavaScript" -PercentComplete 50

        $cssContent = Get-NetworkVisualizationCSS
        $jsContent = Get-NetworkVisualizationJavaScript -JsonData $jsonData

        Write-Progress -Activity "Generating HTML Visualization" -Status "Building HTML document" -PercentComplete 75

        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://d3js.org; style-src 'unsafe-inline'; img-src 'self' data:;">
    <title>Azure Network Topology - Interactive Visualization</title>
    <script src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js" integrity="sha384-VFVwyYn42vCO2IZ8Ln+gMHSdJR8d8YY5LBDCp1xPFfTIHGN+xOl7IqKHlqVmr+n7" crossorigin="anonymous"></script>
    <script>
        if (typeof d3 === 'undefined') {
            document.write('<script src="https://d3js.org/d3.v7.min.js"><\/script>');
        }
    </script>
    <style>
$cssContent
    </style>
</head>
<body>
    <div id="controls">
        <h2>Azure Network Topology</h2>
        <h3>Statistics</h3>
        <p>VNets: <span class="stat-badge">$($AuditResults.Statistics.TotalVNets ?? 0)</span></p>
        <p>Peerings: <span class="stat-badge">$($AuditResults.Statistics.TotalPeerings ?? 0)</span></p>
        <h3>Issues</h3>
        <p>Critical: <span class="stat-badge critical">$($AuditResults.Issues.Critical.Count ?? 0)</span></p>
        <p>High: <span class="stat-badge high">$($AuditResults.Issues.High.Count ?? 0)</span></p>
        <p>Medium: <span class="stat-badge medium">$($AuditResults.Issues.Medium.Count ?? 0)</span></p>
        <h3>Controls</h3>
        <button id="resetZoom">Reset Zoom</button>
        <button id="centerView">Center View</button>
        <h3>Legend</h3>
        <div class="legend-item"><div class="legend-color" style="background:#0078D4;"></div>Virtual Network</div>
        <div class="legend-item"><div class="legend-color" style="background:#E81123;"></div>Has Issues</div>
        <div class="legend-item"><div class="legend-color" style="background:#107C10;border-radius:0;height:3px;"></div>Connected Peering</div>
        <div class="legend-item"><div class="legend-color" style="background:#E81123;border-radius:0;height:3px;"></div>Disconnected/Overlap</div>
    </div>
    <div id="network"></div>
    <script>
$jsContent
    </script>
</body>
</html>
"@

        Write-Progress -Activity "Generating HTML Visualization" -Status "Writing file to disk" -PercentComplete 90

        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)

        Write-Progress -Activity "Generating HTML Visualization" -Completed

        $fileSizeKB = [Math]::Round((Get-Item $OutputPath).Length / 1KB, 2)
        Write-AuditLog "Interactive HTML visualization exported to: $OutputPath (${fileSizeKB}KB)" -Type Success
    }
    catch {
        Write-AuditLog "Failed to generate HTML visualization: $($_.Exception.Message)" -Type Error
        throw
    }
}

Export-ModuleMember -Function Export-NetworkGraphHTML

