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

Describe "WhatIf Support" -Tag 'WhatIf', 'Behavior' {

    Context "Report Generation with -WhatIf" {

        BeforeEach {
            $script:reportPath = Join-Path $script:TestOutputPath "whatif-test-$(New-Guid)"
        }

        It "Should NOT create HTML file when -WhatIf is specified" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -WhatIf | Out-Null

            $expectedHtmlPath = "$($script:reportPath)_Dashboard.html"
            Test-Path $expectedHtmlPath | Should -Be $false
        }

        It "Should NOT create CSV files when -WhatIf is specified" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -WhatIf | Out-Null

            $expectedCsvPath = "$($script:reportPath)_VNets.csv"
            Test-Path $expectedCsvPath | Should -Be $false
        }

        It "Should return empty file arrays when -WhatIf is specified" {
            $result = New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -WhatIf

            $result.HTMLFiles | Should -BeNullOrEmpty
            $result.CSVFiles | Should -BeNullOrEmpty
        }

        It "Should execute without errors with -WhatIf" {
            { New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -WhatIf -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "Report Generation WITHOUT -WhatIf" {

        BeforeEach {
            $script:reportPath = Join-Path $script:TestOutputPath "normal-test-$(New-Guid)"
        }

        It "Should create HTML file when -WhatIf is NOT specified" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -Confirm:$false | Out-Null

            $expectedHtmlPath = "$($script:reportPath)_Dashboard.html"
            Test-Path $expectedHtmlPath | Should -Be $true
        }

        It "Should create CSV files when -WhatIf is NOT specified" {
            $result = New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -Confirm:$false

            $result.CSVFiles.Count | Should -BeGreaterThan 0

            foreach ($csvFile in $result.CSVFiles) {
                Test-Path $csvFile | Should -Be $true
            }
        }

        It "Should return file paths when -WhatIf is NOT specified" {
            $result = New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -Confirm:$false

            $result.HTMLFiles | Should -Not -BeNullOrEmpty
            $result.CSVFiles | Should -Not -BeNullOrEmpty
        }
    }

    Context "SkipHTML Parameter with -WhatIf" {

        BeforeEach {
            $script:reportPath = Join-Path $script:TestOutputPath "skip-html-whatif-test-$(New-Guid)"
        }

        It "Should NOT create HTML when both -SkipHTML and -WhatIf are specified" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -SkipHTML -WhatIf | Out-Null

            $expectedHtmlPath = "$($script:reportPath)_Dashboard.html"
            Test-Path $expectedHtmlPath | Should -Be $false
        }

        It "Should NOT create CSV when -WhatIf is specified even if -SkipHTML is used" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -SkipHTML -WhatIf | Out-Null

            $expectedCsvPath = "$($script:reportPath)_VNets.csv"
            Test-Path $expectedCsvPath | Should -Be $false
        }
    }

    Context "SkipCSV Parameter with -WhatIf" {

        BeforeEach {
            $script:reportPath = Join-Path $script:TestOutputPath "skip-csv-whatif-test-$(New-Guid)"
        }

        It "Should NOT create CSV files when both -SkipCSV and -WhatIf are specified" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -SkipCSV -WhatIf | Out-Null

            $expectedCsvPath = "$($script:reportPath)_VNets.csv"
            Test-Path $expectedCsvPath | Should -Be $false
        }

        It "Should NOT create HTML when -WhatIf is specified even if -SkipCSV is used" {
            New-AuditReport -AuditResults (Get-MockAuditResults) -ReportBasePath $script:reportPath -SkipCSV -WhatIf | Out-Null

            $expectedHtmlPath = "$($script:reportPath)_Dashboard.html"
            Test-Path $expectedHtmlPath | Should -Be $false
        }
    }

    Context "ShouldProcess Behavior" {

        BeforeEach {
            $script:reportPath = Join-Path $script:TestOutputPath "shouldprocess-test-$(New-Guid)"
        }

        It "Should support -WhatIf common parameter" {
            $command = Get-Command New-AuditReport
            $command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        It "Should support -Confirm common parameter" {
            $command = Get-Command New-AuditReport
            $command.Parameters.ContainsKey('Confirm') | Should -Be $true
        }

        It "Should have SupportsShouldProcess attribute" {
            $command = Get-Command New-AuditReport
            $command.CmdletBinding | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
