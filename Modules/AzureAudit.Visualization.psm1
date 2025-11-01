Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Visualization\Exporters\AzureAudit.Visualization.JSON.psm1" -Force
Import-Module "$PSScriptRoot\Visualization\Exporters\AzureAudit.Visualization.DOT.psm1" -Force
Import-Module "$PSScriptRoot\Visualization\Exporters\AzureAudit.Visualization.HTML.psm1" -Force
Import-Module "$PSScriptRoot\Visualization\Exporters\AzureAudit.Visualization.Mermaid.psm1" -Force
Import-Module "$PSScriptRoot\Visualization\Exporters\AzureAudit.Visualization.DrawIO.psm1" -Force

$script:AzureColorScheme = @{
    VNet = "#0078D4"
    Subnet = "#50E6FF"
    PrivateEndpoint = "#8B00FF"
    DNSZone = "#00B294"
    NSG = "#E81123"
    RouteTable = "#FF8C00"
    Peering = "#8A8886"
    Issue = "#E81123"
    Healthy = "#107C10"
    Warning = "#FFB900"
}

function Export-NetworkVisualization {
    <#
    .SYNOPSIS
        Exports Azure network topology to multiple visualization formats.

    .DESCRIPTION
        Master function for exporting Azure network audit results to various visualization
        formats. Orchestrates generation of JSON, DOT/Graphviz, HTML, Mermaid, and Draw.io
        formats. Supports optional timestamping of output files and WhatIf processing.
        Returns array of generated file paths for downstream processing.

    .PARAMETER AuditResults
        Hashtable containing comprehensive Azure network audit results including VNets,
        subnets, peerings, private DNS zones, private endpoints, VNet links, statistics,
        and identified security issues. This is the master data structure for all exports.

    .PARAMETER OutputBasePath
        Base path for output files without extension. Format-specific extensions will be
        appended automatically. Example: "C:\Reports\network" becomes "network.json",
        "network.dot", "network.html", etc.

    .PARAMETER Formats
        Array of format names to export. Valid values: "JSON", "DOT", "SVG", "PNG",
        "HTML", "Mermaid", "DrawIO". Defaults to @("JSON", "DOT", "HTML").
        Multiple formats can be specified simultaneously.

    .PARAMETER GraphvizPath
        Path to Graphviz dot executable for DOT/SVG/PNG rendering. Defaults to "dot"
        (assumes in PATH). If not found, function attempts auto-detection. Only used
        when DOT, SVG, or PNG formats requested.

    .PARAMETER IncludeTimestamp
        Switch to append timestamp (yyyyMMdd_HHmmss) to output file names. Useful for
        versioning and archival purposes. Creates unique files on each export.

    .OUTPUTS
        System.String[]. Array of full file paths for all successfully generated files.
        Returns empty array if WhatIf specified or no files generated.

    .EXAMPLE
        Export-NetworkVisualization -AuditResults $results -OutputBasePath "C:\Reports\network"
        Exports to JSON, DOT, and HTML formats with default settings.

    .EXAMPLE
        Export-NetworkVisualization -AuditResults $results -OutputBasePath ".\output\net" -Formats @("JSON", "HTML", "Mermaid") -IncludeTimestamp
        Exports to three formats with timestamp appended to filenames.

    .EXAMPLE
        $files = Export-NetworkVisualization -AuditResults $results -OutputBasePath ".\net" -Formats @("DOT", "SVG", "PNG") -GraphvizPath "C:\Graphviz\bin\dot.exe"
        Exports Graphviz formats using specific dot executable path.

    .EXAMPLE
        Export-NetworkVisualization -AuditResults $results -OutputBasePath ".\test" -WhatIf
        Shows what would be exported without actually creating files.

    .NOTES
        Supported formats:
        - JSON: NetJSON protocol network graph (standard format)
        - DOT: Graphviz source file with hierarchical layout
        - SVG: Scalable vector graphics (requires Graphviz)
        - PNG: Raster image (requires Graphviz)
        - HTML: Interactive D3.js visualization (standalone)
        - Mermaid: Markdown diagram format (first 20 VNets)
        - DrawIO: CSV import format for diagrams.net

        Dependencies:
        - Graphviz required for DOT/SVG/PNG rendering (auto-detected)
        - HTML format requires modern web browser with JavaScript

        All files use UTF-8 encoding without BOM for maximum compatibility
        SupportsShouldProcess: Yes (WhatIf and Confirm supported)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputBasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$Formats = @("JSON", "DOT", "HTML"),

        [Parameter(Mandatory = $false)]
        [string]$GraphvizPath = "dot",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeTimestamp
    )

    Write-AuditLog "Starting network visualization export..." -Type Progress
    Write-AuditLog "Formats: $($Formats -join ', ')" -Type Info

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $basePathWithTimestamp = if ($IncludeTimestamp) {
        "${OutputBasePath}_${timestamp}"
    } else {
        $OutputBasePath
    }

    if ($PSCmdlet.ShouldProcess("Network Visualization", "Export $($Formats.Count) visualization format(s) to $basePathWithTimestamp")) {
        $exports = [System.Collections.Generic.List[string]]::new()
        $totalFormats = $Formats.Count
        $currentFormat = 0

        if ($Formats -contains "JSON") {
            $currentFormat++
            Write-Progress -Activity 'Network Visualization Export' -Status "Exporting JSON format ($currentFormat of $totalFormats)..." -PercentComplete ([int](($currentFormat / $totalFormats) * 100))
            $jsonPath = "${basePathWithTimestamp}_NetworkGraph.json"
            Export-NetworkGraphJSON -AuditResults $AuditResults -OutputPath $jsonPath
            $exports.Add($jsonPath)
        }

        if ($Formats -contains "DOT" -or $Formats -contains "SVG" -or $Formats -contains "PNG") {
            $currentFormat++
            Write-Progress -Activity 'Network Visualization Export' -Status "Exporting Graphviz formats ($currentFormat of $totalFormats)..." -PercentComplete ([int](($currentFormat / $totalFormats) * 100))
            $dotPath = "${basePathWithTimestamp}_NetworkGraph.dot"
            Export-NetworkGraphDOT -AuditResults $AuditResults -OutputPath $dotPath -GraphvizPath $GraphvizPath
            $exports.Add($dotPath)

            if (Test-Path ($dotPath.Replace('.dot', '.svg'))) {
                $exports.Add($dotPath.Replace('.dot', '.svg'))
            }
            if (Test-Path ($dotPath.Replace('.dot', '.png'))) {
                $exports.Add($dotPath.Replace('.dot', '.png'))
            }
        }

        if ($Formats -contains "HTML") {
            $currentFormat++
            Write-Progress -Activity 'Network Visualization Export' -Status "Exporting interactive HTML ($currentFormat of $totalFormats)..." -PercentComplete ([int](($currentFormat / $totalFormats) * 100))
            $htmlPath = "${basePathWithTimestamp}_NetworkGraph_Interactive.html"
            Export-NetworkGraphHTML -AuditResults $AuditResults -OutputPath $htmlPath
            $exports.Add($htmlPath)
        }

        if ($Formats -contains "Mermaid") {
            $currentFormat++
            Write-Progress -Activity 'Network Visualization Export' -Status "Exporting Mermaid diagram ($currentFormat of $totalFormats)..." -PercentComplete ([int](($currentFormat / $totalFormats) * 100))
            $mermaidPath = "${basePathWithTimestamp}_NetworkDiagram.mmd"
            Export-MermaidDiagram -AuditResults $AuditResults -OutputPath $mermaidPath
            $exports.Add($mermaidPath)
        }

        if ($Formats -contains "DrawIO") {
            $currentFormat++
            Write-Progress -Activity 'Network Visualization Export' -Status "Exporting Draw.io CSV ($currentFormat of $totalFormats)..." -PercentComplete ([int](($currentFormat / $totalFormats) * 100))
            $drawioPath = "${basePathWithTimestamp}_NetworkDiagram_DrawIO.csv"
            Export-DrawIOCSV -AuditResults $AuditResults -OutputPath $drawioPath
            $exports.Add($drawioPath)
        }

        Write-Progress -Activity 'Network Visualization Export' -Completed

        Write-AuditLog "Network visualization export complete!" -Type Success
        Write-AuditLog "Exported $($exports.Count) visualization files" -Type Info

        return [string[]]$exports
    }
    else {
        Write-AuditLog "Network visualization export skipped due to WhatIf" -Type Info
        return [string[]]@()
    }
}

Export-ModuleMember -Function Export-NetworkVisualization
Export-ModuleMember -Variable AzureColorScheme
