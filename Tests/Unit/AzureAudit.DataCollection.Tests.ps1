BeforeAll {
    $ErrorActionPreference = 'Stop'
    $InformationPreference = 'Continue'

    $ProjectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $ModulePath = Join-Path $ProjectRoot "Modules\DataCollection\AzureAudit.DataCollection.psm1"

    Import-Module $ModulePath -Force
    Import-Module (Join-Path $ProjectRoot "Modules\Core\AzureAudit.Logging.psm1") -Force

    Mock Write-AuditLog {} -ModuleName AzureAudit.DataCollection
    Mock Write-Progress {} -ModuleName AzureAudit.DataCollection
}

Describe "DataCollection Module - Core Functions" {

    Context "Invoke-WithRetry Success Scenarios" {

        It "Should execute scriptblock successfully on first attempt" {
            $script:executed = $false
            $result = Invoke-WithRetry -ScriptBlock {
                $script:executed = $true
                return "success"
            } -OperationName "TestOp"

            $result | Should -Be "success"
            $script:executed | Should -Be $true
        }

        It "Should return value from scriptblock" {
            $result = Invoke-WithRetry -ScriptBlock {
                return 42
            }

            $result | Should -Be 42
        }

        It "Should pass complex objects through scriptblock" {
            $testObject = @{ Id = "test"; Value = 100 }
            $result = Invoke-WithRetry -ScriptBlock {
                return $testObject
            }

            $result.Id | Should -Be "test"
            $result.Value | Should -Be 100
        }

        It "Should accept custom MaxRetries parameter" {
            $result = Invoke-WithRetry -ScriptBlock { "ok" } -MaxRetries 3

            $result | Should -Be "ok"
        }

        It "Should accept custom BaseDelaySeconds parameter" {
            $result = Invoke-WithRetry -ScriptBlock { "ok" } -BaseDelaySeconds 1

            $result | Should -Be "ok"
        }

        It "Should accept custom OperationName parameter" {
            $result = Invoke-WithRetry -ScriptBlock { "ok" } -OperationName "CustomOperation"

            $result | Should -Be "ok"
        }
    }

    Context "Invoke-WithRetry Retry Logic" {

        It "Should retry on failure and succeed on second attempt" {
            $script:callCount = 0

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection

            $result = Invoke-WithRetry -ScriptBlock {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    throw "Transient error"
                }
                return "success"
            } -MaxRetries 3 -BaseDelaySeconds 1

            $result | Should -Be "success"
            $script:callCount | Should -Be 2
        }

        It "Should retry specified number of times before throwing" {
            $script:callCount = 0

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    $script:callCount++
                    throw "Persistent error"
                } -MaxRetries 3
            } | Should -Throw

            $script:callCount | Should -Be 3
        }

        It "Should throw original exception after max retries" {
            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Specific error message"
                } -MaxRetries 2
            } | Should -Throw "*Specific error message*"
        }

        It "Should implement exponential backoff delay" {
            $script:callCount = 0
            $script:delays = @()

            Mock Start-Sleep {
                param($Milliseconds)
                $script:delays += $Milliseconds
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    $script:callCount++
                    throw "Error"
                } -MaxRetries 4 -BaseDelaySeconds 1
            } | Should -Throw

            $script:delays.Count | Should -Be 3
            $script:delays[0] | Should -BeGreaterThan 1000
            $script:delays[1] | Should -BeGreaterThan 2000
            $script:delays[2] | Should -BeGreaterThan 4000
        }

        It "Should add random jitter to delays" {
            $script:delays = @()

            Mock Start-Sleep {
                param($Milliseconds)
                $script:delays += $Milliseconds
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Error"
                } -MaxRetries 3 -BaseDelaySeconds 2
            } | Should -Throw

            $script:delays.Count | Should -Be 2
            $script:delays[0] | Should -BeGreaterThan 2000
            $script:delays[0] | Should -BeLessThan 3100
        }

        It "Should cap maximum delay at 60 seconds" {
            $script:delays = @()

            Mock Start-Sleep {
                param($Milliseconds)
                $script:delays += $Milliseconds
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Error"
                } -MaxRetries 10 -BaseDelaySeconds 30
            } | Should -Throw

            $script:delays.Count | Should -BeGreaterThan 0
            $maxDelay = ($script:delays | Measure-Object -Maximum).Maximum
            $maxDelay | Should -BeLessThanOrEqual 61000
        }
    }

    Context "Invoke-WithRetry Error Detection" {

        It "Should detect throttling errors with 429 status" {
            $script:loggedMessages = @()

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection
            Mock Write-AuditLog {
                param($Message, $Type)
                $script:loggedMessages += @{ Message = $Message; Type = $Type }
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "HTTP 429 Too Many Requests"
                } -MaxRetries 2
            } | Should -Throw

            $throttlingMessages = $script:loggedMessages | Where-Object { $_.Message -match "Throttling detected" }
            $throttlingMessages.Count | Should -BeGreaterThan 0
        }

        It "Should detect throttling errors with throttle keyword" {
            $script:loggedMessages = @()

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection
            Mock Write-AuditLog {
                param($Message, $Type)
                $script:loggedMessages += @{ Message = $Message; Type = $Type }
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Request was throttled"
                } -MaxRetries 2
            } | Should -Throw

            $throttlingMessages = $script:loggedMessages | Where-Object { $_.Message -match "Throttling detected" }
            $throttlingMessages.Count | Should -BeGreaterThan 0
        }

        It "Should detect rate limit errors" {
            $script:loggedMessages = @()

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection
            Mock Write-AuditLog {
                param($Message, $Type)
                $script:loggedMessages += @{ Message = $Message; Type = $Type }
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Rate limit exceeded"
                } -MaxRetries 2
            } | Should -Throw

            $throttlingMessages = $script:loggedMessages | Where-Object { $_.Message -match "Throttling detected" }
            $throttlingMessages.Count | Should -BeGreaterThan 0
        }

        It "Should detect timeout errors" {
            $script:loggedMessages = @()

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection
            Mock Write-AuditLog {
                param($Message, $Type)
                $script:loggedMessages += @{ Message = $Message; Type = $Type }
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Operation timed out"
                } -MaxRetries 2
            } | Should -Throw

            $timeoutMessages = $script:loggedMessages | Where-Object { $_.Message -match "Timeout detected" }
            $timeoutMessages.Count | Should -BeGreaterThan 0
        }

        It "Should handle generic errors" {
            $script:loggedMessages = @()

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection
            Mock Write-AuditLog {
                param($Message, $Type)
                $script:loggedMessages += @{ Message = $Message; Type = $Type }
            } -ModuleName AzureAudit.DataCollection

            {
                Invoke-WithRetry -ScriptBlock {
                    throw "Generic error"
                } -MaxRetries 2
            } | Should -Throw

            $errorMessages = $script:loggedMessages | Where-Object { $_.Message -match "Error in" -and $_.Message -match "Generic error" }
            $errorMessages.Count | Should -BeGreaterThan 0
        }
    }

    Context "Invoke-AzResourceGraphWithPagination Single Page" {

        BeforeEach {
            Mock Search-AzGraph {
                param($Query, $Subscription, $First, $SkipToken)
                $items = [System.Collections.ArrayList]@(
                    [PSCustomObject]@{ Id = "resource-1"; Type = "VNet" }
                    [PSCustomObject]@{ Id = "resource-2"; Type = "VNet" }
                    [PSCustomObject]@{ Id = "resource-3"; Type = "VNet" }
                )
                $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value $null
                return $items
            } -ModuleName AzureAudit.DataCollection
        }

        It "Should execute query successfully" {
            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result | Should -Not -BeNullOrEmpty
        }

        It "Should return array of results" {
            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result.GetType().IsArray | Should -Be $true
        }

        It "Should call Search-AzGraph with correct query" {
            Invoke-AzResourceGraphWithPagination -Query "test query" -SubscriptionIds @("sub-1")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $Query -eq "test query"
            }
        }

        It "Should call Search-AzGraph with subscription IDs" {
            Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1", "sub-2")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $Subscription.Count -eq 2 -and $Subscription -contains "sub-1" -and $Subscription -contains "sub-2"
            }
        }

        It "Should use default page size of 1000" {
            Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $First -eq 1000
            }
        }

        It "Should accept custom page size" {
            Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1") -PageSize 500

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $First -eq 500
            }
        }

        It "Should not pass SkipToken on first request" {
            Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $null -eq $SkipToken
            }
        }
    }

    Context "Invoke-AzResourceGraphWithPagination Multiple Pages" {

        BeforeEach {
            $script:pageRequested = 0

            Mock Search-AzGraph {
                param($Query, $Subscription, $First, $SkipToken)
                $script:pageRequested++

                if ($script:pageRequested -eq 1) {
                    $items = [System.Collections.ArrayList]@(
                        [PSCustomObject]@{ Id = "resource-1" }
                        [PSCustomObject]@{ Id = "resource-2" }
                    )
                    $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value "token-page2"
                    return $items
                }
                elseif ($script:pageRequested -eq 2) {
                    $items = [System.Collections.ArrayList]@(
                        [PSCustomObject]@{ Id = "resource-3" }
                        [PSCustomObject]@{ Id = "resource-4" }
                    )
                    $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value "token-page3"
                    return $items
                }
                else {
                    $items = [System.Collections.ArrayList]@(
                        [PSCustomObject]@{ Id = "resource-5" }
                    )
                    $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value $null
                    return $items
                }
            } -ModuleName AzureAudit.DataCollection
        }

        It "Should fetch all pages until no skip token" {
            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -Times 3 -Exactly
        }

        It "Should pass skip token on subsequent requests" {
            Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $SkipToken -eq "token-page2"
            }

            Should -Invoke Search-AzGraph -ModuleName AzureAudit.DataCollection -ParameterFilter {
                $SkipToken -eq "token-page3"
            }
        }

        It "Should combine results from all pages" {
            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result.Count | Should -Be 5
            $result[0].Id | Should -Be "resource-1"
            $result[4].Id | Should -Be "resource-5"
        }
    }

    Context "Invoke-AzResourceGraphWithPagination Empty Results" {

        It "Should handle empty results gracefully" {
            Mock Search-AzGraph {
                $items = [System.Collections.ArrayList]@()
                $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value $null
                return $items
            } -ModuleName AzureAudit.DataCollection

            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result.Count | Should -Be 0
        }

        It "Should handle null results with defensive code" {
            Mock Search-AzGraph {
                $items = [System.Collections.ArrayList]@()
                $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value $null
                return $items
            } -ModuleName AzureAudit.DataCollection

            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result.Count | Should -Be 0
        }
    }

    Context "Invoke-AzResourceGraphWithPagination Integration with Retry" {

        It "Should retry on Search-AzGraph failures" {
            $script:callCount = 0

            Mock Search-AzGraph {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    throw "Transient error"
                }
                $items = [System.Collections.ArrayList]@([PSCustomObject]@{ Id = "resource-1" })
                $items | Add-Member -MemberType NoteProperty -Name "SkipToken" -Value $null
                return $items
            } -ModuleName AzureAudit.DataCollection

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection

            $result = Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")

            $result.Count | Should -Be 1
            $script:callCount | Should -Be 2
        }

        It "Should throw after max retries exhausted" {
            Mock Search-AzGraph {
                throw "Persistent error"
            } -ModuleName AzureAudit.DataCollection

            Mock Start-Sleep {} -ModuleName AzureAudit.DataCollection

            {
                Invoke-AzResourceGraphWithPagination -Query "Resources" -SubscriptionIds @("sub-1")
            } | Should -Throw
        }
    }

    Context "Module Export Verification" {

        It "Should export Invoke-WithRetry function" {
            $module = Get-Module AzureAudit.DataCollection
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-WithRetry"
        }

        It "Should export Invoke-AzResourceGraphWithPagination function" {
            $module = Get-Module AzureAudit.DataCollection
            $module.ExportedFunctions.Keys | Should -Contain "Invoke-AzResourceGraphWithPagination"
        }

        It "Should export all data collection functions" {
            $module = Get-Module AzureAudit.DataCollection
            $module.ExportedFunctions.Count | Should -BeGreaterThan 2
        }
    }
}
