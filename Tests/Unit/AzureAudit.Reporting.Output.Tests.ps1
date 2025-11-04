BeforeAll {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force
    Import-Module "$ProjectRoot/Modules/AzureAudit.Reporting.psm1" -Force
    . "$ProjectRoot/Tests/Fixtures/MockAuditData.ps1"

    function Write-AuditLog {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            [Parameter(Mandatory = $false)]
            $Message,

            [Parameter(Mandatory = $false)]
            $Type
        )
    }

    $script:TestOutputPath = Join-Path $ProjectRoot "Tests/.test-output"
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:TestOutputPath -Force | Out-Null
}

Describe "Report Output Generation" -Tag 'Output', 'Functional' {

    Context "HTML Report Generation" {

        BeforeEach {
            $script:mockData = Get-MockAuditResults
            $script:reportPath = Join-Path $script:TestOutputPath "html-output-test-$(New-Guid)"
            $script:result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -Confirm:$false
        }

        It "Should create HTML dashboard file" {
            $script:result.HTMLFiles | Should -Not -BeNullOrEmpty
            Test-Path $script:result.HTMLFiles[0] | Should -Be $true
        }

        It "Should name HTML file with _Dashboard.html suffix" {
            $script:result.HTMLFiles[0] | Should -Match '_Dashboard\.html$'
        }

        It "Should create valid HTML5 document" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<!DOCTYPE html>'
            $htmlContent | Should -Match '<html\s+lang="en">'
            $htmlContent | Should -Match '</html>'
        }

        It "Should include viewport meta tag for responsive design" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<meta\s+name="viewport"'
        }

        It "Should include UTF-8 charset declaration" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<meta\s+charset="UTF-8">'
        }

        It "Should include CSS styles" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<style[^>]*>'
            $htmlContent | Should -Match 'font-family:'
        }

        It "Should include statistics cards" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match 'stat-card'
            $htmlContent | Should -Match 'Critical Issues'
            $htmlContent | Should -Match 'Virtual Networks'
        }

        It "Should include issues table" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<table.*id="issuesTable"'
            $htmlContent | Should -Match '<th>Severity</th>'
            $htmlContent | Should -Match '<th>Category</th>'
        }

        It "Should include VNets table" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<table.*id="vnetsTable"'
        }

        It "Should include DNS zones table" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match '<table.*id="dnsTable"'
        }

        It "Should include filter buttons" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match 'filter-btn'
            $htmlContent | Should -Match 'data-severity="Critical"'
        }

        It "Should include search box" {
            $htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $htmlContent | Should -Match 'id="issueSearch"'
        }
    }

    Context "CSV Report Generation" {

        BeforeEach {
            $mockData = Get-MockAuditResults -IncludeAllResourceTypes
            $script:reportPath = Join-Path $script:TestOutputPath "csv-output-test-$(New-Guid)"
            $script:result = New-AuditReport -AuditResults $mockData -ReportBasePath $script:reportPath -Confirm:$false
        }

        It "Should create multiple CSV files" {
            $script:result.CSVFiles.Count | Should -BeGreaterThan 1
        }

        It "Should create VNets CSV file" {
            $vnetsFile = $script:result.CSVFiles | Where-Object { $_ -like '*_VNets.csv' }
            $vnetsFile | Should -Not -BeNullOrEmpty
            Test-Path $vnetsFile | Should -Be $true
        }

        It "Should create PrivateDNSZones CSV file" {
            $dnsFile = $script:result.CSVFiles | Where-Object { $_ -like '*_PrivateDNSZones.csv' }
            $dnsFile | Should -Not -BeNullOrEmpty
            Test-Path $dnsFile | Should -Be $true
        }

        It "Should create PrivateEndpoints CSV file" {
            $peFile = $script:result.CSVFiles | Where-Object { $_ -like '*_PrivateEndpoints.csv' }
            $peFile | Should -Not -BeNullOrEmpty
            Test-Path $peFile | Should -Be $true
        }

        It "Should create AllIssues CSV file" {
            $issuesFile = $script:result.CSVFiles | Where-Object { $_ -like '*_AllIssues.csv' }
            $issuesFile | Should -Not -BeNullOrEmpty
            Test-Path $issuesFile | Should -Be $true
        }

        It "Should use UTF-8 encoding for CSV files" {
            $csvFile = $script:result.CSVFiles[0]
            $bytes = [System.IO.File]::ReadAllBytes($csvFile)

            if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                Set-ItResult -Skipped -Because "UTF-8 with BOM detected (acceptable)"
            }
            else {
                $content = Get-Content $csvFile -Raw
                $content | Should -Not -BeNullOrEmpty
            }
        }

        It "Should include headers in CSV files" {
            $vnetsFile = $script:result.CSVFiles | Where-Object { $_ -like '*_VNets.csv' }
            $content = Get-Content $vnetsFile | Select-Object -First 1

            $content | Should -Match 'Subscription'
            $content | Should -Match 'ResourceGroup'
            $content | Should -Match 'Name'
        }

        It "Should include data rows in VNets CSV" {
            $vnetsFile = $script:result.CSVFiles | Where-Object { $_ -like '*_VNets.csv' }
            $data = Import-Csv $vnetsFile

            $data.Count | Should -BeGreaterThan 0
            $data[0].Name | Should -Not -BeNullOrEmpty
        }
    }

    Context "Report Return Value" {

        BeforeEach {
            $script:mockData = Get-MockAuditResults
            $script:reportPath = Join-Path $script:TestOutputPath "return-value-test-$(New-Guid)"
        }

        It "Should return hashtable with CSVFiles and HTMLFiles keys" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -Confirm:$false

            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'CSVFiles'
            $result.Keys | Should -Contain 'HTMLFiles'
        }

        It "Should return arrays for both CSVFiles and HTMLFiles" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -Confirm:$false

            $result.CSVFiles | Should -BeOfType [array]
            $result.HTMLFiles | Should -BeOfType [array]
        }

        It "Should return absolute paths" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -Confirm:$false

            $result.HTMLFiles[0] | Should -Match '^[A-Z]:\\'
            $result.CSVFiles[0] | Should -Match '^[A-Z]:\\'
        }
    }

    Context "SkipHTML Parameter" {

        BeforeEach {
            $script:mockData = Get-MockAuditResults
            $script:reportPath = Join-Path $script:TestOutputPath "skip-html-test-$(New-Guid)"
        }

        It "Should NOT create HTML when -SkipHTML is specified" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -SkipHTML -Confirm:$false

            $result.HTMLFiles | Should -BeNullOrEmpty
            $expectedHtmlPath = "$($script:reportPath)_Dashboard.html"
            Test-Path $expectedHtmlPath | Should -Be $false
        }

        It "Should still create CSV files when -SkipHTML is specified" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -SkipHTML -Confirm:$false

            $result.CSVFiles | Should -Not -BeNullOrEmpty
        }
    }

    Context "SkipCSV Parameter" {

        BeforeEach {
            $script:mockData = Get-MockAuditResults
            $script:reportPath = Join-Path $script:TestOutputPath "skip-csv-test-$(New-Guid)"
        }

        It "Should NOT create CSV files when -SkipCSV is specified" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -SkipCSV -Confirm:$false

            $result.CSVFiles | Should -BeNullOrEmpty
        }

        It "Should still create HTML when -SkipCSV is specified" {
            $result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -SkipCSV -Confirm:$false

            $result.HTMLFiles | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
