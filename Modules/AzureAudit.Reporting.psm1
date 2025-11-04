Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Reporting\CSV\AzureAudit.Reporting.CSV.psm1" -Force
Import-Module "$PSScriptRoot\Reporting\HTML\AzureAudit.Reporting.HTML.Components.psm1" -Force

function New-AuditReport {
    <#
    .SYNOPSIS
    Generates comprehensive audit reports in CSV and HTML formats from Azure network audit results.

    .DESCRIPTION
    The New-AuditReport function orchestrates the creation of multiple audit report formats including structured
    CSV data exports and interactive HTML dashboards. The function supports ShouldProcess for WhatIf and Confirm
    operations, allowing safe preview of report generation actions. It processes Azure audit results containing
    virtual networks, private DNS zones, private endpoints, and security issues into professional, shareable reports
    suitable for compliance documentation, security analysis, and stakeholder communication.

    The function generates an interactive HTML dashboard with real-time filtering, search capabilities, and
    responsive design optimized for both desktop and mobile viewing. CSV exports provide structured data for
    integration with data analysis tools, SIEM systems, and compliance frameworks.

    .PARAMETER AuditResults
    A hashtable containing the complete audit results from Azure network scanning operations. The hashtable must
    contain the following properties:
    - VNets: Array of virtual network objects with subscription, resource group, name, location, address spaces
    - PrivateDNSZones: Array of DNS zone objects with record sets and VNet link information
    - PrivateEndpoints: Array of private endpoint objects with connection states and target resources
    - Issues: Nested hashtable with severity levels (Critical, High, Medium, Low, Info) containing issue arrays
    - Statistics: Hashtable with aggregate counts for TotalVNets, TotalPrivateDNSZones, and other metrics

    .PARAMETER ReportBasePath
    The base file path for all generated report files. This path serves as a prefix for CSV and HTML outputs with
    appropriate suffixes and extensions automatically appended. The parent directory must exist and be writable.
    Example: "C:\Reports\AzureAudit_2025-01-15" generates files like "AzureAudit_2025-01-15_VNets.csv" and
    "AzureAudit_2025-01-15_Dashboard.html". Do not include file extensions in this parameter.

    .PARAMETER SkipCSV
    When specified, suppresses the generation of CSV report files. Use this switch when only HTML dashboard output
    is required or when CSV data has already been exported in a previous operation. This parameter does not affect
    HTML report generation.

    .PARAMETER SkipHTML
    When specified, suppresses the generation of the HTML dashboard file. Use this switch when only CSV data exports
    are required or when dashboard generation is being handled by a separate process. This parameter does not affect
    CSV report generation.

    .EXAMPLE
    $auditData = Invoke-AzureNetworkAudit -SubscriptionId "12345678-1234-1234-1234-123456789012"
    $reports = New-AuditReport -AuditResults $auditData -ReportBasePath "C:\Reports\AzureAudit_2025-01-15"

    Generates both CSV and HTML reports from audit data with the specified base path, returning a hashtable
    containing arrays of generated file paths.

    .EXAMPLE
    New-AuditReport -AuditResults $results -ReportBasePath ".\output\audit" -SkipCSV

    Generates only the HTML dashboard, skipping CSV file exports for faster execution when structured data is not needed.

    .EXAMPLE
    $reportFiles = New-AuditReport -AuditResults $data -ReportBasePath "C:\Audit\Report" -WhatIf

    Previews report generation actions without creating any files using the WhatIf parameter for validation.

    .EXAMPLE
    New-AuditReport -AuditResults $results -ReportBasePath "C:\Reports\Audit" -SkipHTML -Confirm:$false

    Generates only CSV reports without interactive confirmation prompts for automated pipeline execution.

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable containing two keys:
    - CSVFiles: Array of absolute file paths for all successfully generated CSV reports
    - HTMLFiles: Array of absolute file paths for all successfully generated HTML dashboard files

    The hashtable structure allows easy iteration over generated files for upload, archival, or notification
    operations. Empty arrays are returned for skipped report types. File paths are absolute regardless of
    whether relative paths were provided in ReportBasePath.

    .NOTES
    Author: Azure Audit Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later
    Dependencies:
    - Export-CSVReports function from AzureAudit.Reporting.CSV module
    - Get-DashboardCSS function from AzureAudit.Reporting.HTML.Components module
    - ConvertTo-DashboardJSON function from AzureAudit.Reporting.HTML.Components module
    - Write-AuditLog function must be available in the session

    The function supports PowerShell's common parameters including:
    - WhatIf: Preview report generation without creating files
    - Confirm: Prompt for confirmation before generating each report type
    - Verbose: Display detailed progress information during execution
    - ErrorAction: Control error handling behavior

    Generated HTML dashboards include:
    - Interactive severity-based filtering for issues
    - Real-time search across all issue fields
    - Responsive grid layouts for all device sizes
    - Severity-coded visual indicators (Critical=Red, High=Orange, Medium=Yellow)
    - Tabular displays for VNets, DNS zones, and private endpoints
    - Statistics cards showing aggregate counts
    - Modern gradient design with smooth animations

    Generated CSV reports include:
    - VNets: Virtual network configurations with subnets and peering counts
    - PrivateDNSZones: DNS zones with record sets and registration links
    - PrivateEndpoints: Private endpoint details with connection states
    - AllIssues: Combined issues across all severity levels
    - CriticalIssues: Filtered view of critical severity issues only

    All files use UTF-8 encoding without BOM for maximum compatibility with modern tools and platforms.
    The function logs all operations using Write-AuditLog with appropriate severity levels for monitoring
    and troubleshooting.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults,

        [Parameter(Mandatory = $true)]
        [string]$ReportBasePath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCSV,

        [Parameter(Mandatory = $false)]
        [switch]$SkipHTML
    )

    Write-AuditLog "Generating audit reports..." -Type Progress

    $reportFiles = @{
        CSVFiles = @()
        HTMLFiles = @()
    }

    if (-not $SkipCSV) {
        if ($PSCmdlet.ShouldProcess("CSV reports", "Export")) {
            $csvFiles = Export-CSVReports -AuditResults $AuditResults -ReportBasePath $ReportBasePath
            $reportFiles.CSVFiles = $csvFiles
        }
    }

    if (-not $SkipHTML) {
        if ($PSCmdlet.ShouldProcess("HTML dashboard", "Generate")) {
            $htmlFile = "${ReportBasePath}_Dashboard.html"

            $jsonData = ConvertTo-DashboardJSON -AuditResults $AuditResults
            $cssContent = Get-DashboardCSS

            $nonceBytes = New-Object byte[] 32
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
            $nonce = [Convert]::ToBase64String($nonceBytes)

            $totalVNets = if ($AuditResults.ContainsKey('Statistics')) { $AuditResults.Statistics.TotalVNets ?? 0 } else { 0 }
            $totalDNSZones = if ($AuditResults.ContainsKey('Statistics')) { $AuditResults.Statistics.TotalPrivateDNSZones ?? 0 } else { 0 }

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self' data:; object-src 'none'; base-uri 'self';">
    <title>Azure Network Audit Dashboard</title>
    <style nonce="$nonce">
$cssContent
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Azure Network Audit Dashboard</h1>
            <div class="meta">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="number">$($AuditResults.Issues.Critical.Count ?? 0)</div>
                <div class="label">Critical Issues</div>
            </div>
            <div class="stat-card high">
                <div class="number">$($AuditResults.Issues.High.Count ?? 0)</div>
                <div class="label">High Issues</div>
            </div>
            <div class="stat-card medium">
                <div class="number">$($AuditResults.Issues.Medium.Count ?? 0)</div>
                <div class="label">Medium Issues</div>
            </div>
            <div class="stat-card success">
                <div class="number">$totalVNets</div>
                <div class="label">Virtual Networks</div>
            </div>
            <div class="stat-card info">
                <div class="number">$totalDNSZones</div>
                <div class="label">DNS Zones</div>
            </div>
        </div>

        <div class="content-grid">
            <div class="card full-width">
                <h2>Issues Overview</h2>
                <div class="search-box">
                    <input type="text" id="issueSearch" placeholder="Search issues...">
                </div>
                <div class="filter-buttons">
                    <button class="filter-btn active" data-severity="all">All</button>
                    <button class="filter-btn" data-severity="Critical">Critical</button>
                    <button class="filter-btn" data-severity="High">High</button>
                    <button class="filter-btn" data-severity="Medium">Medium</button>
                </div>
                <div class="action-buttons">
                    <button class="action-btn" id="exportBtn">Export Filtered to CSV</button>
                    <button class="action-btn secondary" id="groupBtn">Group by Subscription</button>
                    <button class="action-btn secondary" id="resetBtn">Reset Grouping</button>
                </div>
                <table id="issuesTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Title</th>
                            <th>Resource</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="issuesTableBody">
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Virtual Networks</h2>
                <table id="vnetsTable">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Location</th>
                            <th>Subnets</th>
                            <th>State</th>
                        </tr>
                    </thead>
                    <tbody id="vnetsTableBody">
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Private DNS Zones</h2>
                <table id="dnsTable">
                    <thead>
                        <tr>
                            <th>Zone Name</th>
                            <th>Record Sets</th>
                            <th>VNet Links</th>
                            <th>State</th>
                        </tr>
                    </thead>
                    <tbody id="dnsTableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script type="application/json" id="issues-data">
$($jsonData.IssuesJson)
    </script>
    <script type="application/json" id="vnets-data">
$($jsonData.VNetsJson)
    </script>
    <script type="application/json" id="dns-data">
$($jsonData.DNSZonesJson)
    </script>

    <script nonce="$nonce">
        const issues = JSON.parse(document.getElementById('issues-data').textContent);
        const vnets = JSON.parse(document.getElementById('vnets-data').textContent);
        const dnsZones = JSON.parse(document.getElementById('dns-data').textContent);

        let currentFilter = 'all';

        function createTableRow(cells) {
            const row = document.createElement('tr');
            cells.forEach(cellData => {
                const cell = document.createElement('td');
                if (cellData.badge) {
                    const badge = document.createElement('span');
                    badge.className = 'badge ' + cellData.badge;
                    badge.textContent = cellData.text;
                    cell.appendChild(badge);
                } else {
                    cell.textContent = cellData;
                }
                row.appendChild(cell);
            });
            return row;
        }

        function renderIssues() {
            const tbody = document.getElementById('issuesTableBody');
            const searchTerm = document.getElementById('issueSearch').value.toLowerCase();

            const filtered = issues.filter(issue => {
                const matchesFilter = currentFilter === 'all' || issue.severity === currentFilter;
                const matchesSearch = !searchTerm ||
                    issue.title.toLowerCase().includes(searchTerm) ||
                    issue.description.toLowerCase().includes(searchTerm) ||
                    issue.resourceName.toLowerCase().includes(searchTerm);
                return matchesFilter && matchesSearch;
            });

            const fragment = document.createDocumentFragment();
            filtered.forEach(issue => {
                const row = createTableRow([
                    { text: issue.severity, badge: issue.severity.toLowerCase() },
                    issue.category,
                    issue.title,
                    issue.resourceName,
                    issue.description
                ]);
                fragment.appendChild(row);
            });
            tbody.replaceChildren(fragment);
        }

        function renderVNets() {
            const tbody = document.getElementById('vnetsTableBody');
            const fragment = document.createDocumentFragment();

            vnets.forEach(vnet => {
                const row = createTableRow([
                    vnet.name,
                    vnet.location,
                    vnet.subnetCount,
                    { text: vnet.provisioningState, badge: vnet.provisioningState === 'Succeeded' ? 'succeeded' : 'failed' }
                ]);
                fragment.appendChild(row);
            });
            tbody.replaceChildren(fragment);
        }

        function renderDNSZones() {
            const tbody = document.getElementById('dnsTableBody');
            const fragment = document.createDocumentFragment();

            dnsZones.forEach(zone => {
                const row = createTableRow([
                    zone.name,
                    zone.recordSets,
                    zone.vnetLinks,
                    { text: zone.provisioningState, badge: zone.provisioningState === 'Succeeded' ? 'succeeded' : 'failed' }
                ]);
                fragment.appendChild(row);
            });
            tbody.replaceChildren(fragment);
        }

        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentFilter = this.dataset.severity;
                renderIssues();
            });
        });

        document.getElementById('issueSearch').addEventListener('input', renderIssues);

        document.getElementById('exportBtn').addEventListener('click', exportFilteredToCSV);
        document.getElementById('groupBtn').addEventListener('click', groupBySubscription);
        document.getElementById('resetBtn').addEventListener('click', resetGrouping);

        function getCurrentFilteredIssues() {
            const searchTerm = document.getElementById('issueSearch').value.toLowerCase();
            return issues.filter(issue => {
                const matchesFilter = currentFilter === 'all' || issue.severity === currentFilter;
                const matchesSearch = !searchTerm ||
                    issue.title.toLowerCase().includes(searchTerm) ||
                    issue.description.toLowerCase().includes(searchTerm) ||
                    issue.resourceName.toLowerCase().includes(searchTerm);
                return matchesFilter && matchesSearch;
            });
        }

        function convertToCSV(data) {
            if (data.length === 0) return '';

            const headers = ['Severity', 'Category', 'Title', 'Resource Name', 'Description', 'Remediation'];
            const csvRows = [headers.join(',')];

            data.forEach(issue => {
                const row = [
                    issue.severity,
                    issue.category,
                    '"' + (issue.title || '').replace(/"/g, '""') + '"',
                    '"' + (issue.resourceName || '').replace(/"/g, '""') + '"',
                    '"' + (issue.description || '').replace(/"/g, '""') + '"',
                    '"' + (issue.remediation || '').replace(/"/g, '""') + '"'
                ];
                csvRows.push(row.join(','));
            });

            return csvRows.join('\\n');
        }

        function downloadFile(content, filename, contentType) {
            const blob = new Blob([content], { type: contentType });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        }

        function exportFilteredToCSV() {
            const filtered = getCurrentFilteredIssues();
            if (filtered.length === 0) {
                alert('No issues to export with current filters');
                return;
            }
            const csv = convertToCSV(filtered);
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            downloadFile(csv, 'azure-audit-issues-' + timestamp + '.csv', 'text/csv');
        }

        let isGroupedBySubscription = false;

        function groupBySubscription() {
            isGroupedBySubscription = true;
            const filtered = getCurrentFilteredIssues();

            const grouped = {};
            filtered.forEach(issue => {
                const subId = issue.subscriptionId || 'Unknown';
                if (!grouped[subId]) {
                    grouped[subId] = [];
                }
                grouped[subId].push(issue);
            });

            const tbody = document.getElementById('issuesTableBody');
            const fragment = document.createDocumentFragment();

            const sortedSubs = Object.keys(grouped).sort();

            sortedSubs.forEach(subId => {
                const subIssues = grouped[subId];

                const headerRow = document.createElement('tr');
                headerRow.className = 'subscription-header';
                const headerCell = document.createElement('td');
                headerCell.colSpan = 5;
                headerCell.innerHTML = '<strong>Subscription: ' + subId + '</strong> (' + subIssues.length + ' issues)';
                headerRow.appendChild(headerCell);
                fragment.appendChild(headerRow);

                subIssues.forEach(issue => {
                    const row = createTableRow([
                        { text: issue.severity, badge: issue.severity.toLowerCase() },
                        issue.category,
                        issue.title,
                        issue.resourceName,
                        issue.description
                    ]);
                    fragment.appendChild(row);
                });
            });

            tbody.replaceChildren(fragment);
        }

        function resetGrouping() {
            isGroupedBySubscription = false;
            renderIssues();
        }

        renderIssues();
        renderVNets();
        renderDNSZones();
    </script>
</body>
</html>
"@

            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($htmlFile, $html, $utf8NoBom)
            Write-AuditLog "Generated HTML dashboard: $htmlFile" -Type Success
            $reportFiles.HTMLFiles += $htmlFile
        }
    }

    Write-AuditLog "Report generation complete" -Type Success
    $reportFiles.CSVFiles = @($reportFiles.CSVFiles)
    $reportFiles.HTMLFiles = @($reportFiles.HTMLFiles)
    return $reportFiles
}

Export-ModuleMember -Function New-AuditReport
