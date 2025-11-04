BeforeAll {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force
    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Authentication.psm1" -Force

    function Write-AuditLog {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            [Parameter(Mandatory = $false)]
            $Message,

            [Parameter(Mandatory = $false)]
            $Type
        )
    }

    $InformationPreference = 'Continue'
}

Describe "Authentication Module" -Tag 'Authentication', 'Critical' {

    Context "Connect-AzureForAudit Interactive Authentication" {

        BeforeEach {
            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = "test-tenant-id" }
                        Account = @{ Id = "test-account@example.com" }
                    }
                }
            } -ModuleName AzureAudit.Authentication
        }

        It "Should call Connect-AzAccount without parameters for interactive auth" {
            Connect-AzureForAudit

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $null -eq $ServicePrincipal -and $null -eq $Credential -and $null -eq $Tenant
            }
        }

        It "Should not throw when interactive authentication succeeds" {
            { Connect-AzureForAudit } | Should -Not -Throw
        }

        It "Should return successfully for interactive authentication" {
            $result = Connect-AzureForAudit
            $result | Should -Not -BeNull
        }

        It "Should handle Connect-AzAccount returning null" {
            Mock Connect-AzAccount {
                return $null
            } -ModuleName AzureAudit.Authentication

            { Connect-AzureForAudit } | Should -Throw "*no context was returned*"
        }

        It "Should throw when Connect-AzAccount fails" {
            Mock Connect-AzAccount {
                throw "Authentication failed"
            } -ModuleName AzureAudit.Authentication

            { Connect-AzureForAudit } | Should -Throw
        }
    }

    Context "Connect-AzureForAudit Service Principal Authentication" {

        BeforeEach {
            $script:testClientId = "test-client-id-123"
            $script:testTenantId = "test-tenant-id-456"
            $script:testSecret = ConvertTo-SecureString "test-secret" -AsPlainText -Force

            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = $TenantId }
                        Account = @{ Id = $Credential.UserName }
                    }
                }
            } -ModuleName AzureAudit.Authentication
        }

        It "Should call Connect-AzAccount with ServicePrincipal parameter" {
            Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $ServicePrincipal -eq $true
            }
        }

        It "Should pass correct TenantId to Connect-AzAccount" {
            Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $Tenant -eq $script:testTenantId
            }
        }

        It "Should pass PSCredential with ClientId as username" {
            Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $Credential.UserName -eq $script:testClientId
            }
        }

        It "Should not throw when service principal authentication succeeds" {
            { Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId } |
                Should -Not -Throw
        }

        It "Should handle Connect-AzAccount returning null for service principal" {
            Mock Connect-AzAccount {
                return $null
            } -ModuleName AzureAudit.Authentication

            { Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId } |
                Should -Throw "*no context was returned*"
        }

        It "Should throw when service principal authentication fails" {
            Mock Connect-AzAccount {
                throw "Service principal authentication failed"
            } -ModuleName AzureAudit.Authentication

            { Connect-AzureForAudit -ClientId $script:testClientId -ClientSecret $script:testSecret -TenantId $script:testTenantId } |
                Should -Throw
        }

        It "Should use interactive auth when only ClientId is provided" {
            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = "interactive-tenant" }
                        Account = @{ Id = "interactive-user@example.com" }
                    }
                }
            } -ModuleName AzureAudit.Authentication

            Connect-AzureForAudit -ClientId $script:testClientId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $null -eq $ServicePrincipal
            }
        }

        It "Should use interactive auth when only ClientSecret is provided" {
            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = "interactive-tenant" }
                        Account = @{ Id = "interactive-user@example.com" }
                    }
                }
            } -ModuleName AzureAudit.Authentication

            Connect-AzureForAudit -ClientSecret $script:testSecret

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $null -eq $ServicePrincipal
            }
        }

        It "Should use interactive auth when only TenantId is provided" {
            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = "interactive-tenant" }
                        Account = @{ Id = "interactive-user@example.com" }
                    }
                }
            } -ModuleName AzureAudit.Authentication

            Connect-AzureForAudit -TenantId $script:testTenantId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $null -eq $ServicePrincipal
            }
        }

        It "Should use interactive auth when ClientId and TenantId provided but not ClientSecret" {
            Mock Connect-AzAccount {
                return @{
                    Context = @{
                        Tenant = @{ Id = "interactive-tenant" }
                        Account = @{ Id = "interactive-user@example.com" }
                    }
                }
            } -ModuleName AzureAudit.Authentication

            Connect-AzureForAudit -ClientId $script:testClientId -TenantId $script:testTenantId

            Should -Invoke Connect-AzAccount -ModuleName AzureAudit.Authentication -Times 1 -Exactly -ParameterFilter {
                $null -eq $ServicePrincipal
            }
        }
    }

    Context "Get-AuditSubscriptions All Subscriptions" {

        BeforeEach {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                    [PSCustomObject]@{ Id = "sub-2"; Name = "Subscription 2"; State = "Enabled" }
                    [PSCustomObject]@{ Id = "sub-3"; Name = "Subscription 3"; State = "Disabled" }
                    [PSCustomObject]@{ Id = "sub-4"; Name = "Subscription 4"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication
        }

        It "Should call Get-AzSubscription when no IDs provided" {
            Get-AuditSubscriptions

            Should -Invoke Get-AzSubscription -ModuleName AzureAudit.Authentication -Times 1 -Exactly
        }

        It "Should return only enabled subscriptions" {
            $result = Get-AuditSubscriptions

            $result.Count | Should -Be 3
            $result | ForEach-Object { $_.State | Should -Be "Enabled" }
        }

        It "Should exclude disabled subscriptions" {
            $result = Get-AuditSubscriptions

            $result.Id | Should -Not -Contain "sub-3"
        }

        It "Should return array of subscriptions" {
            $result = Get-AuditSubscriptions

            $result.GetType().IsArray | Should -Be $true
            $result.Count | Should -Be 3
        }

        It "Should handle single enabled subscription" {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication

            $result = Get-AuditSubscriptions

            $result.Count | Should -Be 1
            $result[0].Id | Should -Be "sub-1"
        }

        It "Should throw when no enabled subscriptions found" {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Disabled" }
                )
            } -ModuleName AzureAudit.Authentication

            { Get-AuditSubscriptions } | Should -Throw "*No enabled subscriptions found*"
        }

        It "Should throw when Get-AzSubscription fails" {
            Mock Get-AzSubscription {
                throw "Failed to retrieve subscriptions"
            } -ModuleName AzureAudit.Authentication

            { Get-AuditSubscriptions } | Should -Throw
        }

        It "Should handle empty subscription list" {
            Mock Get-AzSubscription {
                return @()
            } -ModuleName AzureAudit.Authentication

            { Get-AuditSubscriptions } | Should -Throw "*No enabled subscriptions found*"
        }
    }

    Context "Get-AuditSubscriptions Specific Subscription IDs" {

        BeforeEach {
            Mock Get-AzSubscription {
                param($SubscriptionId)

                $allSubs = @{
                    "sub-1" = [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                    "sub-2" = [PSCustomObject]@{ Id = "sub-2"; Name = "Subscription 2"; State = "Enabled" }
                    "sub-3" = [PSCustomObject]@{ Id = "sub-3"; Name = "Subscription 3"; State = "Disabled" }
                    "sub-4" = [PSCustomObject]@{ Id = "sub-4"; Name = "Subscription 4"; State = "Enabled" }
                }

                if ($SubscriptionId -and $allSubs.ContainsKey($SubscriptionId)) {
                    return $allSubs[$SubscriptionId]
                }
                throw "Subscription $SubscriptionId not found"
            } -ModuleName AzureAudit.Authentication
        }

        It "Should call Get-AzSubscription for each provided ID" {
            Get-AuditSubscriptions -SubscriptionIds "sub-1", "sub-2"

            Should -Invoke Get-AzSubscription -ModuleName AzureAudit.Authentication -Times 2 -Exactly
        }

        It "Should return only specified enabled subscriptions" {
            $result = Get-AuditSubscriptions -SubscriptionIds "sub-1", "sub-2"

            $result.Count | Should -Be 2
            $result.Id | Should -Contain "sub-1"
            $result.Id | Should -Contain "sub-2"
        }

        It "Should exclude disabled subscriptions from specified IDs" {
            $result = Get-AuditSubscriptions -SubscriptionIds "sub-1", "sub-3"

            $result.Count | Should -Be 1
            $result[0].Id | Should -Be "sub-1"
        }

        It "Should handle single subscription ID" {
            $result = Get-AuditSubscriptions -SubscriptionIds "sub-1"

            $result.Count | Should -Be 1
            $result[0].Id | Should -Be "sub-1"
        }

        It "Should throw when all specified subscriptions are disabled" {
            { Get-AuditSubscriptions -SubscriptionIds "sub-3" } | Should -Throw "*No enabled subscriptions found*"
        }

        It "Should throw when subscription ID does not exist" {
            { Get-AuditSubscriptions -SubscriptionIds "non-existent-sub" } | Should -Throw
        }

        It "Should handle mix of valid and invalid subscription IDs" {
            Mock Get-AzSubscription {
                param($SubscriptionId)

                if ($SubscriptionId -eq "sub-1") {
                    return [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                }
                throw "Subscription $SubscriptionId not found"
            } -ModuleName AzureAudit.Authentication

            { Get-AuditSubscriptions -SubscriptionIds "sub-1", "invalid-sub" } | Should -Throw
        }

        It "Should validate all IDs before returning results" {
            $result = Get-AuditSubscriptions -SubscriptionIds "sub-1", "sub-2", "sub-4"

            $result.Count | Should -Be 3
            Should -Invoke Get-AzSubscription -ModuleName AzureAudit.Authentication -Times 3 -Exactly
        }
    }

    Context "Get-AuditSubscriptions Parameter Validation" {

        BeforeEach {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication
        }

        It "Should accept empty array for SubscriptionIds" {
            { Get-AuditSubscriptions -SubscriptionIds @() } | Should -Not -Throw
        }

        It "Should handle empty array same as no parameter" {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                    [PSCustomObject]@{ Id = "sub-2"; Name = "Subscription 2"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication

            $result1 = Get-AuditSubscriptions
            $result2 = Get-AuditSubscriptions -SubscriptionIds @()

            $result1.Count | Should -Be $result2.Count
        }

        It "Should not accept null for SubscriptionIds" {
            { Get-AuditSubscriptions -SubscriptionIds $null } | Should -Throw
        }
    }

    Context "Get-AuditSubscriptions Return Value" {

        BeforeEach {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication
        }

        It "Should return array even for single subscription" {
            $result = Get-AuditSubscriptions

            $result.GetType().IsArray | Should -Be $true
            $result.Count | Should -Be 1
        }

        It "Should preserve subscription properties" {
            $result = Get-AuditSubscriptions

            $result[0].Id | Should -Be "sub-1"
            $result[0].Name | Should -Be "Subscription 1"
            $result[0].State | Should -Be "Enabled"
        }

        It "Should return subscriptions in order" {
            Mock Get-AzSubscription {
                return @(
                    [PSCustomObject]@{ Id = "sub-1"; Name = "Subscription 1"; State = "Enabled" }
                    [PSCustomObject]@{ Id = "sub-2"; Name = "Subscription 2"; State = "Enabled" }
                    [PSCustomObject]@{ Id = "sub-3"; Name = "Subscription 3"; State = "Enabled" }
                )
            } -ModuleName AzureAudit.Authentication

            $result = Get-AuditSubscriptions

            $result.Count | Should -Be 3
            $result[0].Id | Should -Be "sub-1"
            $result[1].Id | Should -Be "sub-2"
            $result[2].Id | Should -Be "sub-3"
        }
    }

    Context "Module Export Verification" {

        It "Should export Connect-AzureForAudit function" {
            $commands = Get-Command -Module AzureAudit.Authentication
            $commands.Name | Should -Contain "Connect-AzureForAudit"
        }

        It "Should export Get-AuditSubscriptions function" {
            $commands = Get-Command -Module AzureAudit.Authentication
            $commands.Name | Should -Contain "Get-AuditSubscriptions"
        }

        It "Should export exactly 2 functions" {
            $commands = Get-Command -Module AzureAudit.Authentication
            $commands.Count | Should -Be 2
        }
    }
}

AfterAll {
}
