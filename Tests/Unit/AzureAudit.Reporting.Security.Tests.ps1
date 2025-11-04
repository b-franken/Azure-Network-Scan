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

Describe "HTML Dashboard Security" -Tag 'Security', 'Critical' {

    Context "CSP Nonce Generation" {

        BeforeEach {
            $script:mockData = Get-MockAuditResults -IncludeXSSAttempts
            $script:reportPath = Join-Path $script:TestOutputPath "security-test-$(New-Guid)"
            $script:result = New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:reportPath -Confirm:$false
            $script:htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
        }

        It "Should generate a unique nonce for each report" {
            $mockData = Get-MockAuditResults
            $reportPath1 = Join-Path $script:TestOutputPath "nonce-test-1-$(New-Guid)"
            $reportPath2 = Join-Path $script:TestOutputPath "nonce-test-2-$(New-Guid)"

            $result1 = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath1 -Confirm:$false
            $result2 = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath2 -Confirm:$false

            $html1 = Get-Content $result1.HTMLFiles[0] -Raw
            $html2 = Get-Content $result2.HTMLFiles[0] -Raw

            $html1 -match "nonce-([A-Za-z0-9+/=]+)" | Should -Be $true
            $nonce1 = $matches[1]

            $html2 -match "nonce-([A-Za-z0-9+/=]+)" | Should -Be $true
            $nonce2 = $matches[1]

            $nonce1 | Should -Not -Be $nonce2
        }

        It "Should generate nonce with at least 128 bits of entropy (32 hex chars or 24 base64 chars)" {
            $script:htmlContent -match "nonce-([A-Za-z0-9+/=]+)" | Should -Be $true
            $nonce = $matches[1]

            $nonce.Length | Should -BeGreaterOrEqual 24
        }

        It "Should include nonce in Content-Security-Policy header" {
            $script:htmlContent -match '<meta.*Content-Security-Policy.*content="([^"]+)"' | Should -Be $true
            $cspHeader = $matches[1]

            $cspHeader | Should -Match "script-src 'nonce-[A-Za-z0-9+/=]+'"
        }

        It "Should include nonce in script tag" {
            $htmlContent -match "nonce-([A-Za-z0-9+/=]+)" | Should -Be $true
            $nonce = $matches[1]

            $htmlContent | Should -Match "<script nonce=`"$nonce`">"
        }

        It "Should include nonce in style tag" {
            $htmlContent -match "nonce-([A-Za-z0-9+/=]+)" | Should -Be $true
            $nonce = $matches[1]

            $htmlContent | Should -Match "<style nonce=`"$nonce`">"
        }
    }

    Context "Content Security Policy Configuration" {

        BeforeEach {
            $mockData = Get-MockAuditResults
            $reportPath = Join-Path $script:TestOutputPath "csp-test-$(New-Guid)"
            $result = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath -Confirm:$false
            $script:htmlContent = Get-Content $result.HTMLFiles[0] -Raw

            $script:htmlContent -match '<meta.*Content-Security-Policy.*content="([^"]+)"' | Out-Null
            $script:cspHeader = $matches[1]
        }

        It "Should NOT include 'unsafe-inline' in script-src" {
            $script:cspHeader | Should -Not -Match "script-src[^;]*'unsafe-inline'"
        }

        It "Should NOT include 'unsafe-inline' in style-src" {
            $script:cspHeader | Should -Not -Match "style-src[^;]*'unsafe-inline'"
        }

        It "Should include object-src 'none' to prevent Flash/plugin attacks" {
            $script:cspHeader | Should -Match "object-src 'none'"
        }

        It "Should include base-uri directive to prevent base tag injection" {
            $script:cspHeader | Should -Match "base-uri 'self'"
        }

        It "Should restrict default-src appropriately" {
            $script:cspHeader | Should -Match "default-src 'self'"
        }

        It "Should allow data: URIs for images (for inline chart rendering)" {
            $script:cspHeader | Should -Match "img-src[^;]*data:"
        }
    }

    Context "XSS Protection - JSON Escaping" {

        BeforeEach {
            $mockData = Get-MockAuditResults -IncludeXSSAttempts
            $reportPath = Join-Path $script:TestOutputPath "xss-test-$(New-Guid)"
            $result = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath -Confirm:$false
            $script:htmlContent = Get-Content $result.HTMLFiles[0] -Raw
        }

        It "Should escape <script> tags in JSON data" {
            $script:htmlContent | Should -Not -Match '<script type="application/json"[^>]*>[^<]*<script>'
            $script:htmlContent | Should -Match '\\u003cscript\\u003e'
        }

        It "Should escape </script> closing tags in JSON data" {
            $script:htmlContent | Should -Not -Match '<script type="application/json"[^>]*>[^<]*</script[^>]*>[^<]*</script>'
            $script:htmlContent | Should -Match '\\u003c/script\\u003e'
        }

        It "Should escape HTML entities in JSON strings" {
            $script:htmlContent -match '<script type="application/json" id="issues-data">(.*?)</script>' | Should -Be $true
            $jsonData = $matches[1].Trim()

            $jsonData | Should -Match '\\u003c'
            $jsonData | Should -Match '\\u003e'
        }

        It "Should escape single and double quotes properly" {
            $script:htmlContent -match '<script type="application/json" id="issues-data">(.*?)</script>' | Should -Be $true
            $jsonData = $matches[1].Trim()

            $parsedData = $jsonData | ConvertFrom-Json -ErrorAction Stop
            $parsedData | Should -Not -BeNullOrEmpty
        }

        It "Should parse JSON data without errors despite XSS attempts" {
            $script:htmlContent -match '<script type="application/json" id="issues-data">(.*?)</script>' | Should -Be $true
            $jsonData = $matches[1].Trim()

            { $jsonData | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "Inline Handler Removal" {

        BeforeEach {
            $mockData = Get-MockAuditResults
            $reportPath = Join-Path $script:TestOutputPath "inline-test-$(New-Guid)"
            $result = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath -Confirm:$false
            $script:htmlContent = Get-Content $result.HTMLFiles[0] -Raw
        }

        It "Should NOT contain any onclick handlers" {
            $script:htmlContent | Should -Not -Match 'onclick\s*='
        }

        It "Should NOT contain any onload handlers" {
            $script:htmlContent | Should -Not -Match 'onload\s*='
        }

        It "Should NOT contain any onerror handlers" {
            $script:htmlContent | Should -Not -Match 'onerror\s*='
        }

        It "Should NOT contain any onmouseover handlers" {
            $script:htmlContent | Should -Not -Match 'onmouseover\s*='
        }

        It "Should use addEventListener for export button" {
            $script:htmlContent | Should -Match "getElementById\('exportBtn'\)\.addEventListener\('click'"
        }

        It "Should use addEventListener for group button" {
            $script:htmlContent | Should -Match "getElementById\('groupBtn'\)\.addEventListener\('click'"
        }

        It "Should use addEventListener for reset button" {
            $script:htmlContent | Should -Match "getElementById\('resetBtn'\)\.addEventListener\('click'"
        }
    }

    Context "JSON Data Separation" {

        BeforeEach {
            $mockData = Get-MockAuditResults
            $reportPath = Join-Path $script:TestOutputPath "json-separation-test-$(New-Guid)"
            $result = New-AuditReport -AuditResults $mockData -ReportBasePath $reportPath -Confirm:$false
            $script:htmlContent = Get-Content $result.HTMLFiles[0] -Raw
        }

        It "Should embed JSON in application/json script tags" {
            $script:htmlContent | Should -Match '<script type="application/json" id="issues-data">'
            $script:htmlContent | Should -Match '<script type="application/json" id="vnets-data">'
            $script:htmlContent | Should -Match '<script type="application/json" id="dns-data">'
        }

        It "Should parse JSON from DOM using getElementById" {
            $script:htmlContent | Should -Match "JSON\.parse\(document\.getElementById\('issues-data'\)\.textContent\)"
            $script:htmlContent | Should -Match "JSON\.parse\(document\.getElementById\('vnets-data'\)\.textContent\)"
            $script:htmlContent | Should -Match "JSON\.parse\(document\.getElementById\('dns-data'\)\.textContent\)"
        }

        It "Should NOT directly assign JSON to JavaScript variables" {
            $script:htmlContent | Should -Not -Match 'const issues = \[{.*}\];'
            $script:htmlContent | Should -Not -Match 'const vnets = \[{.*}\];'
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
