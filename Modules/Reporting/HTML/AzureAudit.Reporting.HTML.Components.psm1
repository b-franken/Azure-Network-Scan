Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DashboardCSS {
    <#
    .SYNOPSIS
    Generates the CSS stylesheet for the Azure Audit HTML dashboard.

    .DESCRIPTION
    The Get-DashboardCSS function returns a comprehensive CSS stylesheet string designed for the Azure Network Audit
    interactive HTML dashboard. The stylesheet implements a modern, responsive design with gradient backgrounds,
    card-based layouts, and interactive elements including hover effects, tabs, and severity-based color coding.
    The CSS is optimized for both desktop and mobile viewing with media queries for responsive breakpoints.

    .EXAMPLE
    $css = Get-DashboardCSS
    $htmlContent = "<style>$css</style>"

    Retrieves the CSS stylesheet and embeds it in an HTML style tag for dashboard generation.

    .EXAMPLE
    Get-DashboardCSS | Out-File -FilePath ".\dashboard-styles.css" -Encoding UTF8

    Exports the CSS stylesheet to a standalone file for external reference or customization.

    .OUTPUTS
    System.String
    Returns a multi-line string containing complete CSS stylesheet definitions for all dashboard components including
    layout grids, stat cards, tables, badges, tabs, search boxes, and responsive media queries. The output is ready
    for direct embedding in HTML documents.

    .NOTES
    Author: Azure Audit Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later

    The generated CSS includes styling for:
    - Responsive grid layouts with auto-fit columns
    - Severity-based color coding (Critical=Red, High=Orange, Medium=Yellow, Info=Blue, Success=Green)
    - Interactive elements with smooth transitions and hover effects
    - Tabbed content containers with active state styling
    - Data tables with alternating row highlights
    - Badge components for status and severity indicators
    - Search input fields with focus states
    - Mobile-responsive breakpoints at 768px
    - Modern gradient backgrounds using linear-gradient

    The stylesheet uses the Segoe UI font family as the primary typeface with web-safe fallbacks. All colors
    follow modern accessibility guidelines with sufficient contrast ratios. The design is compatible with all
    modern browsers including Edge, Chrome, Firefox, and Safari.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @"
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header .meta {
            color: #666;
            font-size: 14px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card .number {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stat-card.critical .number { color: #e74c3c; }
        .stat-card.high .number { color: #e67e22; }
        .stat-card.medium .number { color: #f39c12; }
        .stat-card.success .number { color: #27ae60; }
        .stat-card.info .number { color: #3498db; }
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .card.full-width {
            grid-column: 1 / -1;
        }
        .card h2 {
            color: #333;
            font-size: 20px;
            margin-bottom: 20px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #ecf0f1;
        }
        .tab {
            background: none;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-size: 14px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
        }
        .tab:hover {
            color: #3498db;
        }
        .tab.active {
            color: #3498db;
            border-bottom-color: #3498db;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        table th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        table td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        table tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge.critical { background: #fee; color: #c00; }
        .badge.high { background: #ffe; color: #e67e22; }
        .badge.medium { background: #fff4e6; color: #f39c12; }
        .badge.low { background: #e8f5e9; color: #4caf50; }
        .badge.info { background: #e3f2fd; color: #2196f3; }
        .badge.succeeded { background: #e8f5e9; color: #4caf50; }
        .badge.failed { background: #fee; color: #c00; }
        .search-box {
            margin-bottom: 20px;
        }
        .search-box input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .search-box input:focus {
            outline: none;
            border-color: #3498db;
        }
        canvas {
            max-width: 100%;
            height: auto;
        }
        .filter-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 16px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .filter-btn:hover {
            border-color: #3498db;
            color: #3498db;
        }
        .filter-btn.active {
            background: #3498db;
            color: white;
            border-color: #3498db;
        }
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
"@
}

function ConvertTo-DashboardJSON {
    <#
    .SYNOPSIS
    Converts Azure audit results into JSON-ready data structures for interactive dashboard rendering.

    .DESCRIPTION
    The ConvertTo-DashboardJSON function transforms complex Azure audit result hashtables into optimized data
    structures suitable for JSON serialization and JavaScript consumption in HTML dashboards. The function performs
    data aggregation, categorization, and transformation to create chart-ready datasets and filterable table data.
    It processes issues, virtual networks, and DNS zones into normalized formats with all required fields for
    client-side rendering.

    .PARAMETER AuditResults
    A hashtable containing the complete audit results from Azure network scanning operations. The hashtable must
    contain properties for Issues, VNets, and PrivateDNSZones. The Issues property should be structured as nested
    hashtables with severity levels (Critical, High, Medium, Low, Info) containing arrays of issue objects.

    .EXAMPLE
    $jsonData = ConvertTo-DashboardJSON -AuditResults $auditResults
    $issuesJson = $jsonData.IssuesJson
    $vnetsJson = $jsonData.VNetsJson

    Converts audit results to dashboard-ready JSON data and extracts specific JSON strings for embedding.

    .EXAMPLE
    $dashboardData = ConvertTo-DashboardJSON -AuditResults $results
    $html = "<script>const issues = $($dashboardData.IssuesJson);</script>"

    Transforms audit data and embeds the JSON directly into JavaScript variable declarations within HTML.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable containing the following keys:
    - IssuesJson: JSON array string of all issues with severity, category, title, description, resource details
    - VNetsJson: JSON array string of virtual networks with subscription, resource group, location, address spaces
    - DNSZonesJson: JSON array string of DNS zones with record sets, VNet links, and provisioning states
    - CategoryLabels: Comma-separated string of issue category names for chart labels
    - CategoryData: Comma-separated string of issue counts per category for chart data points

    All JSON strings are compressed and properly escaped for direct embedding in HTML script tags. Empty arrays
    are represented as "[]" strings to prevent JavaScript errors.

    .NOTES
    Author: Azure Audit Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later

    The function performs the following data transformations:
    - Aggregates issues by category with severity-level breakdowns
    - Calculates total issue counts per category for chart visualization
    - Normalizes VNet data including subnet and peering counts with null coalescing
    - Transforms DNS zone data with registration link statistics
    - Sorts category labels alphabetically for consistent chart ordering
    - Compresses JSON output using -Compress flag for reduced payload sizes
    - Uses -Depth 10 for nested object serialization to prevent data truncation
    - Applies -AsArray flag to ensure single-item arrays serialize correctly

    The output is specifically designed for consumption by Chart.js and vanilla JavaScript in modern browsers.
    All timestamps are converted to string format to ensure proper JSON serialization and client-side parsing.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    $issuesByCategory = @{}
    foreach ($severity in @("Critical", "High", "Medium", "Low", "Info")) {
        foreach ($issue in $AuditResults.Issues[$severity]) {
            if (!$issuesByCategory.ContainsKey($issue.Category)) {
                $issuesByCategory[$issue.Category] = @{
                    Critical = 0
                    High = 0
                    Medium = 0
                    Low = 0
                    Info = 0
                }
            }
            $issuesByCategory[$issue.Category][$severity]++
        }
    }

    $categoryChartData = @()
    $categoryChartLabels = @()
    foreach ($category in $issuesByCategory.Keys | Sort-Object) {
        $categoryChartLabels += "'$category'"
        $total = $issuesByCategory[$category].Critical + $issuesByCategory[$category].High +
                 $issuesByCategory[$category].Medium + $issuesByCategory[$category].Low
        $categoryChartData += $total
    }

    $allIssuesJson = @("Critical", "High", "Medium", "Low", "Info") | ForEach-Object {
        $severity = $_
        $AuditResults.Issues[$severity] | ForEach-Object {
            @{
                timestamp = ($_.Timestamp -as [string])
                severity = $severity
                category = $_.Category
                title = $_.Title
                description = $_.Description
                resourceName = $_.ResourceName
                resourceType = $_.ResourceType
                subscriptionId = $_.SubscriptionId
                remediation = $_.Remediation
            }
        }
    }

    $vnetsJsonArray = $AuditResults.VNets | ForEach-Object {
        @{
            subscription = $_.subscriptionId
            resourceGroup = $_.resourceGroup
            name = $_.name
            location = $_.location
            addressSpace = ($_.addressSpace -join ', ')
            subnetCount = $_.subnets ? @($_.subnets).Count : 0
            peeringCount = $_.peerings ? @($_.peerings).Count : 0
            provisioningState = $_.provisioningState
        }
    }

    $dnsZonesJsonArray = $AuditResults.PrivateDNSZones | ForEach-Object {
        @{
            subscription = $_.subscriptionId
            resourceGroup = $_.resourceGroup
            name = $_.name
            recordSets = $_.numberOfRecordSets
            vnetLinks = $_.numberOfVirtualNetworkLinks
            linksWithRegistration = $_.numberOfVirtualNetworkLinksWithRegistration
            provisioningState = $_.provisioningState
        }
    }

    return @{
        IssuesJson = @($allIssuesJson).Count -gt 0 ? ($allIssuesJson | ConvertTo-Json -Depth 10 -Compress -AsArray -EscapeHandling EscapeHtml) : '[]'
        VNetsJson = @($vnetsJsonArray).Count -gt 0 ? ($vnetsJsonArray | ConvertTo-Json -Depth 10 -Compress -AsArray -EscapeHandling EscapeHtml) : '[]'
        DNSZonesJson = @($dnsZonesJsonArray).Count -gt 0 ? ($dnsZonesJsonArray | ConvertTo-Json -Depth 10 -Compress -AsArray -EscapeHandling EscapeHtml) : '[]'
        CategoryLabels = $categoryChartLabels -join ','
        CategoryData = $categoryChartData -join ','
    }
}

Export-ModuleMember -Function Get-DashboardCSS, ConvertTo-DashboardJSON
