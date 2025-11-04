$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$ProjectRoot = Split-Path -Parent $PSScriptRoot

$config = New-PesterConfiguration

$config.Run.Path = Join-Path $ProjectRoot "Tests/Unit/AzureAudit.Reporting.*.Tests.ps1"
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = Join-Path $ProjectRoot "Modules/AzureAudit.Reporting.psm1"
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = Join-Path $ProjectRoot "Tests/coverage-reporting.xml"
$config.Output.Verbosity = 'Detailed'

Write-Information "Running code coverage analysis on Reporting module..."
Write-Information "Test path: $($config.Run.Path)"
Write-Information "Module path: $($config.CodeCoverage.Path)"

$result = Invoke-Pester -Configuration $config

Write-Information "`nCode Coverage Summary:"
Write-Information "Lines Covered: $($result.CodeCoverage.CoveragePercent)%"
Write-Information "Commands Executed: $($result.CodeCoverage.CommandsExecutedCount)"
Write-Information "Commands Missed: $($result.CodeCoverage.CommandsMissedCount)"

if ($result.CodeCoverage.CommandsMissedCount -gt 0) {
    Write-Information "`nMissed Commands (first 20):"
    $result.CodeCoverage.CommandsMissed | Select-Object -First 20 | ForEach-Object {
        Write-Information "  Line $($_.Line): $($_.Command)"
    }
}

exit $result.Result
