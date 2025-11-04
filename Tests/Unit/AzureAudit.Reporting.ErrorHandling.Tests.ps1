BeforeAll {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force
    Import-Module "$ProjectRoot/Modules/AzureAudit.Reporting.psm1" -Force

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

Describe "Error Handling and Edge Cases" -Tag 'ErrorHandling', 'Critical' {

    Context "New-AuditReport Parameter Validation" {

        It "Should throw when AuditResults is null" {
            $script:reportPath = Join-Path $script:TestOutputPath "null-test-$(New-Guid)"

            { New-AuditReport -AuditResults $null -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Throw -ErrorId 'ParameterArgumentValidationError*'
        }

        It "Should throw when ReportBasePath is null or empty" {
            $script:mockData = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{ Critical = @(); High = @(); Medium = @(); Low = @(); Info = @() }
                Statistics = @{}
            }

            { New-AuditReport -AuditResults $script:mockData -ReportBasePath $null -Confirm:$false -ErrorAction Stop } |
                Should -Throw -ErrorId 'ParameterArgumentValidationError*'
        }
    }

    Context "Empty or Minimal Data Handling" {

        It "Should handle completely empty audit results without errors" {
            $script:emptyData = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 0
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "empty-data-test-$(New-Guid)"

            { New-AuditReport -AuditResults $script:emptyData -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Not -Throw
        }

        It "Should create valid HTML even with no data" {
            $script:emptyData = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 0
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "empty-html-test-$(New-Guid)"
            $script:result = New-AuditReport -AuditResults $script:emptyData -ReportBasePath $script:reportPath -Confirm:$false

            $script:result.HTMLFiles | Should -Not -BeNullOrEmpty
            Test-Path $script:result.HTMLFiles[0] | Should -Be $true

            $script:htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw
            $script:htmlContent | Should -Match '<!DOCTYPE html>'
        }

        It "Should handle missing Statistics gracefully" {
            $script:dataWithoutStats = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "no-stats-test-$(New-Guid)"

            { New-AuditReport -AuditResults $script:dataWithoutStats -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Not -Throw
        }
    }

    Context "Special Characters in Data" {

        It "Should handle special characters in resource names" {
            $script:specialCharData = @{
                VNets = @(
                    @{
                        subscriptionId = 'test-sub'
                        resourceGroup = 'rg-with-special-chars-&<>"\'''
                        name = 'vnet-with-quotes-"test"'
                        location = 'eastus'
                        addressSpace = @('10.0.0.0/16')
                        subnets = @()
                        peerings = @()
                        dnsServers = @()
                        provisioningState = 'Succeeded'
                    }
                )
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 1
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "special-chars-test-$(New-Guid)"

            { New-AuditReport -AuditResults $script:specialCharData -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Not -Throw
        }

        It "Should escape special characters in JSON output" {
            $script:specialCharData = @{
                VNets = @(
                    @{
                        subscriptionId = 'test-sub'
                        resourceGroup = 'rg-with-ampersand-&-and-quotes-"test"'
                        name = 'vnet-test'
                        location = 'eastus'
                        addressSpace = @('10.0.0.0/16')
                        subnets = @()
                        peerings = @()
                        dnsServers = @()
                        provisioningState = 'Succeeded'
                    }
                )
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 1
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "json-escape-test-$(New-Guid)"
            $script:result = New-AuditReport -AuditResults $script:specialCharData -ReportBasePath $script:reportPath -Confirm:$false

            $script:htmlContent = Get-Content $script:result.HTMLFiles[0] -Raw

            $script:htmlContent | Should -Match 'rg-with-ampersand-'
            $script:htmlContent | Should -Not -Match '<script type="application/json"[^>]*>[^<]*"test"[^<]*</script>'
        }
    }

    Context "File System Error Scenarios" {

        It "Should handle invalid characters in file path gracefully" {
            $script:mockData = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{}
            }
            $script:invalidPath = "C:\<invalid>:path*/test"

            { New-AuditReport -AuditResults $script:mockData -ReportBasePath $script:invalidPath -Confirm:$false -ErrorAction Stop } |
                Should -Throw
        }
    }

    Context "ConvertTo-DashboardJSON Edge Cases" {

        It "Should handle null values in issue properties" {
            $script:nullIssueData = @{
                VNets = @()
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @(
                        @{
                            Timestamp = $null
                            Category = 'Test'
                            Title = 'Test Issue'
                            Description = $null
                            ResourceName = $null
                            ResourceType = 'VNet'
                            SubscriptionId = 'test-sub'
                            Remediation = $null
                        }
                    )
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 0
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "null-issue-test-$(New-Guid)"

            { New-AuditReport -AuditResults $script:nullIssueData -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Not -Throw
        }

        It "Should handle very large datasets without errors" {
            $script:largeDataset = @{
                VNets = 1..100 | ForEach-Object {
                    @{
                        subscriptionId = "sub-$_"
                        resourceGroup = "rg-$_"
                        name = "vnet-$_"
                        location = 'eastus'
                        addressSpace = @("10.$_.0.0/16")
                        subnets = @()
                        peerings = @()
                        dnsServers = @()
                        provisioningState = 'Succeeded'
                    }
                }
                PrivateDNSZones = @()
                PrivateEndpoints = @()
                Issues = @{
                    Critical = @()
                    High = @()
                    Medium = @()
                    Low = @()
                    Info = @()
                }
                Statistics = @{
                    TotalVNets = 100
                    TotalPrivateDNSZones = 0
                }
            }
            $script:reportPath = Join-Path $script:TestOutputPath "large-dataset-test-$(New-Guid)"

            { New-AuditReport -AuditResults $script:largeDataset -ReportBasePath $script:reportPath -Confirm:$false -ErrorAction Stop } |
                Should -Not -Throw
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
