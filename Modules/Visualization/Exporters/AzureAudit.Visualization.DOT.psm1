Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-GraphvizPath {
    <#
    .SYNOPSIS
        Locates Graphviz dot executable on the system.

    .DESCRIPTION
        Searches for the Graphviz dot executable in standard installation locations
        across Windows, Linux, and macOS platforms. Checks common installation paths
        and system PATH environment variable. Returns the first valid path found.

    .OUTPUTS
        System.String. Full path to dot executable, or $null if not found.

    .EXAMPLE
        $dotPath = Find-GraphvizPath
        if ($dotPath) { Write-Information "Found Graphviz at: $dotPath" -InformationAction Continue }
        Locates Graphviz and displays the path.

    .EXAMPLE
        $graphviz = Find-GraphvizPath
        if (-not $graphviz) { throw "Graphviz not installed" }
        Locates Graphviz or throws error if not found.

    .NOTES
        Checked paths:
        - Windows: C:\Program Files\Graphviz\bin\dot.exe, %LOCALAPPDATA%\Programs\Graphviz\bin\dot.exe
        - Linux: /usr/bin/dot, /usr/local/bin/dot
        - macOS: /opt/homebrew/bin/dot
        - System PATH: dot command
        Returns first valid path found, null if none exist
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidatePaths = @(
        "dot",
        "C:\Program Files\Graphviz\bin\dot.exe",
        "C:\Program Files (x86)\Graphviz\bin\dot.exe",
        "/usr/bin/dot",
        "/usr/local/bin/dot",
        "/opt/homebrew/bin/dot",
        "$env:LOCALAPPDATA\Programs\Graphviz\bin\dot.exe"
    )

    foreach ($path in $candidatePaths) {
        if (Test-Path $path -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-AuditLog "Found Graphviz at: $path" -Type Debug
            return $path
        }
    }

    if (Get-Command "dot" -ErrorAction SilentlyContinue) {
        $dotCommand = Get-Command "dot"
        Write-AuditLog "Found Graphviz in PATH: $($dotCommand.Source)" -Type Debug
        return $dotCommand.Source
    }

    Write-AuditLog "Graphviz not found in standard locations" -Type Debug
    return $null
}

function Export-NetworkGraphDOT {
    <#
    .SYNOPSIS
        Exports Azure network topology to Graphviz DOT format with automatic rendering.

    .DESCRIPTION
        Generates a Graphviz DOT diagram representing Azure network infrastructure.
        Creates hierarchical visualization with subscriptions as clusters, virtual
        networks as nodes, and peerings/overlaps as edges. Automatically attempts to
        render DOT file to SVG and PNG formats using Graphviz if available. Highlights
        security issues with color coding.

    .PARAMETER AuditResults
        Hashtable containing Azure network audit results including VNets, peerings,
        and security issues. Must contain VNets array organized by subscription.

    .PARAMETER OutputPath
        Full file path where the DOT file will be saved. SVG and PNG files will be
        generated with same base name if Graphviz is available.

    .PARAMETER GraphvizPath
        Path to Graphviz dot executable. Defaults to "dot" (assumes in PATH).
        If not found at specified location, function auto-detects using Find-GraphvizPath.

    .OUTPUTS
        None. Writes DOT file to disk and attempts to generate SVG/PNG renderings.

    .EXAMPLE
        Export-NetworkGraphDOT -AuditResults $results -OutputPath "C:\Reports\network.dot"
        Generates DOT file and attempts auto-rendering to SVG/PNG.

    .EXAMPLE
        Export-NetworkGraphDOT -AuditResults $results -OutputPath ".\network.dot" -GraphvizPath "C:\Graphviz\bin\dot.exe"
        Generates DOT file using specific Graphviz installation path.

    .NOTES
        Encoding: UTF-8 without BOM
        Visual features:
        - Subscriptions grouped in dashed clusters
        - VNets color-coded: blue (healthy), red (issues)
        - Peerings: green solid (connected), red dashed (disconnected)
        - IP overlaps highlighted with bold red edges
        Auto-renders to SVG and PNG if Graphviz available
        Graphviz installation: https://graphviz.org/download/
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$GraphvizPath = "dot"
    )

    Write-AuditLog "Generating Graphviz DOT diagram..." -Type Progress

    $dot = @"
digraph AzureNetwork {
    rankdir=TB;
    compound=true;
    node [fontname="Arial", fontsize=10];
    edge [fontname="Arial", fontsize=9];
    graph [fontname="Arial", fontsize=12, pad="0.5", nodesep="0.5", ranksep="1.0"];

"@

    $subscriptions = $AuditResults.VNets | Group-Object subscriptionId

    foreach ($sub in $subscriptions) {
        $subName = ($sub.Name -split '/')[-1].Substring(0, [Math]::Min(20, ($sub.Name -split '/')[-1].Length))
        $dot += @"

    subgraph cluster_$($subName.Replace('-','_')) {
        label="Subscription: $subName";
        style=dashed;
        color="#0078D4";
        fontsize=11;

"@

        foreach ($vnet in $sub.Group) {
            $vnetIssues = $AuditResults.Issues.Critical + $AuditResults.Issues.High |
                          Where-Object { $_.ResourceName -eq $vnet.name }

            $vnetIssuesCount = @($vnetIssues).Count
            $color = $vnetIssuesCount -gt 0 ? '#E81123' : '#0078D4'
            $style = $vnetIssuesCount -gt 0 ? 'filled,bold' : 'filled'
            $fillcolor = $vnetIssuesCount -gt 0 ? '#FFE6E6' : '#E6F3FF'

            $label = "$($vnet.name)\n$($vnet.addressSpace -join ', ')\n$($vnet.location)"
            if ($vnetIssuesCount -gt 0) {
                $label += "\n! $vnetIssuesCount Issues"
            }

            $vnetId = $vnet.id.Replace('/', '_').Replace('-', '_')
            $dot += "        `"$vnetId`" [label=`"$label`", shape=box, style=`"$style`", color=`"$color`", fillcolor=`"$fillcolor`", penwidth=2];`n"
        }

        $dot += "    }`n"
    }

    $dot += "`n    // VNet Peerings`n"
    foreach ($vnet in $AuditResults.VNets) {
        if ($vnet.peerings) {
            foreach ($peering in $vnet.peerings) {
                $remoteVNetId = $peering.properties.remoteVirtualNetwork.id

                $sourceId = $vnet.id.Replace('/', '_').Replace('-', '_')
                $targetId = $remoteVNetId.Replace('/', '_').Replace('-', '_')

                $status = $peering.properties.peeringState
                $color = $status -eq 'Connected' ? '#107C10' : '#E81123'
                $style = $status -eq 'Connected' ? 'solid' : 'dashed'

                $dot += "    `"$sourceId`" -> `"$targetId`" [label=`"Peering\n$status`", color=`"$color`", style=$style, dir=both, penwidth=2];`n"
            }
        }
    }

    $ipOverlaps = $AuditResults.Issues.Critical | Where-Object { $_.Category -eq "IP Overlap" }
    if (@($ipOverlaps).Count -gt 0) {
        $dot += "`n    // IP Overlaps (Critical Issues)`n"
        foreach ($overlap in $ipOverlaps) {
            if ($overlap.ResourceName -match '(.*) <-> (.*)') {
                $vnet1Name = $matches[1]
                $vnet2Name = $matches[2]

                $vnet1 = $AuditResults.VNets | Where-Object { $_.name -eq $vnet1Name } | Select-Object -First 1
                $vnet2 = $AuditResults.VNets | Where-Object { $_.name -eq $vnet2Name } | Select-Object -First 1

                if ($vnet1 -and $vnet2) {
                    $sourceId = $vnet1.id.Replace('/', '_').Replace('-', '_')
                    $targetId = $vnet2.id.Replace('/', '_').Replace('-', '_')

                    $dot += "    `"$sourceId`" -> `"$targetId`" [label=`"OVERLAP!`", color=`"#E81123`", style=bold, penwidth=3, constraint=false];`n"
                }
            }
        }
    }

    $dot += "}`n"

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($OutputPath, $dot, $utf8NoBom)
    Write-AuditLog "DOT diagram exported to: $OutputPath" -Type Success

    $effectiveGraphvizPath = $GraphvizPath
    if (-not (Test-Path $GraphvizPath -PathType Leaf -ErrorAction SilentlyContinue) -and
        -not (Get-Command $GraphvizPath -ErrorAction SilentlyContinue)) {
        Write-AuditLog "Graphviz not found at specified path: $GraphvizPath" -Type Debug
        Write-AuditLog "Attempting auto-detection..." -Type Info
        $effectiveGraphvizPath = Find-GraphvizPath
    }

    if ($effectiveGraphvizPath) {
        $svgPath = $OutputPath.Replace('.dot', '.svg')
        $pngPath = $OutputPath.Replace('.dot', '.png')

        try {
            $process = Start-Process -FilePath $effectiveGraphvizPath -ArgumentList "-Tsvg", $OutputPath, "-o", $svgPath -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-AuditLog "Generated SVG diagram: $svgPath" -Type Success
            } else {
                throw "Graphviz exited with code $($process.ExitCode)"
            }

            $process = Start-Process -FilePath $effectiveGraphvizPath -ArgumentList "-Tpng", $OutputPath, "-o", $pngPath -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-AuditLog "Generated PNG diagram: $pngPath" -Type Success
            } else {
                throw "Graphviz exited with code $($process.ExitCode)"
            }
        }
        catch {
            Write-AuditLog "Graphviz execution failed: $($_.Exception.Message)" -Type Warning
            Write-AuditLog "Check Graphviz installation at: $effectiveGraphvizPath" -Type Info
        }
    }
    else {
        Write-AuditLog "Graphviz not found. Checked paths:" -Type Warning
        Write-AuditLog "  - C:\Program Files\Graphviz\bin\dot.exe" -Type Info
        Write-AuditLog "  - C:\Program Files (x86)\Graphviz\bin\dot.exe" -Type Info
        Write-AuditLog "  - /usr/bin/dot" -Type Info
        Write-AuditLog "  - /usr/local/bin/dot" -Type Info
        Write-AuditLog "Install Graphviz from: https://graphviz.org/download/" -Type Info
    }
}

Export-ModuleMember -Function Export-NetworkGraphDOT
