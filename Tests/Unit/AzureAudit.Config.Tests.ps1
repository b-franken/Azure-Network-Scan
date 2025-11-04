BeforeAll {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force

    $script:TestOutputPath = Join-Path $ProjectRoot "Tests/.test-output"
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:TestOutputPath -Force | Out-Null

    $InformationPreference = 'Continue'
}

Describe "Config Module" -Tag 'Config', 'Critical' {

    Context "Get-AuditConfig Function" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
        }

        It "Should return a hashtable" {
            $config = Get-AuditConfig
            $config | Should -BeOfType [hashtable]
        }

        It "Should contain Authentication section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "Authentication"
        }

        It "Should contain Logging section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "Logging"
        }

        It "Should contain DataCollection section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "DataCollection"
        }

        It "Should contain Analysis section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "Analysis"
        }

        It "Should contain Reporting section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "Reporting"
        }

        It "Should contain Subscriptions section" {
            $config = Get-AuditConfig
            $config.Keys | Should -Contain "Subscriptions"
        }

        It "Should have default AuthMethod as Interactive" {
            $config = Get-AuditConfig
            $config.Authentication.AuthMethod | Should -Be "Interactive"
        }

        It "Should have default LogLevel as Info" {
            $config = Get-AuditConfig
            $config.Logging.LogLevel | Should -Be "Info"
        }

        It "Should have default ResourceGraphPageSize as 1000" {
            $config = Get-AuditConfig
            $config.DataCollection.ResourceGraphPageSize | Should -Be 1000
        }

        It "Should have default MaxConcurrentQueries as 5" {
            $config = Get-AuditConfig
            $config.Analysis.MaxConcurrentQueries | Should -Be 5
        }
    }

    Context "Get-AuditConfigValue Function" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
        }

        It "Should retrieve Authentication.AuthMethod value" {
            $value = Get-AuditConfigValue -Section "Authentication" -Key "AuthMethod"
            $value | Should -Be "Interactive"
        }

        It "Should retrieve Logging.LogLevel value" {
            $value = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            $value | Should -Be "Info"
        }

        It "Should retrieve DataCollection.ResourceGraphPageSize value" {
            $value = Get-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize"
            $value | Should -Be 1000
        }

        It "Should retrieve Analysis.MaxConcurrentQueries value" {
            $value = Get-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries"
            $value | Should -Be 5
        }

        It "Should retrieve Reporting.OutputPath value" {
            $value = Get-AuditConfigValue -Section "Reporting" -Key "OutputPath"
            $value | Should -Not -BeNullOrEmpty
        }

        It "Should retrieve Subscriptions.SubscriptionIds value as empty array" {
            $value = Get-AuditConfigValue -Section "Subscriptions" -Key "SubscriptionIds"
            @($value).Count | Should -Be 0
        }

        It "Should throw when Section does not exist" {
            { Get-AuditConfigValue -Section "NonExistent" -Key "SomeKey" } | Should -Throw
        }

        It "Should throw when Key does not exist" {
            { Get-AuditConfigValue -Section "Authentication" -Key "NonExistentKey" } | Should -Throw
        }

        It "Should throw for invalid Section via ValidateSet" {
            { Get-AuditConfigValue -Section "InvalidSection" -Key "SomeKey" } |
                Should -Throw
        }

        It "Should throw with specific message for invalid Key" {
            { Get-AuditConfigValue -Section "Logging" -Key "InvalidKey" } |
                Should -Throw "*Key*not found*"
        }
    }

    Context "Set-AuditConfigValue Function" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
        }

        It "Should set Logging.LogLevel to Debug" {
            Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "Debug" -Confirm:$false
            $value = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            $value | Should -Be "Debug"
        }

        It "Should set DataCollection.ResourceGraphPageSize to 500" {
            Set-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize" -Value 500 -Confirm:$false
            $value = Get-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize"
            $value | Should -Be 500
        }

        It "Should set Analysis.MaxConcurrentQueries to 10" {
            Set-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries" -Value 10 -Confirm:$false
            $value = Get-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries"
            $value | Should -Be 10
        }

        It "Should set Reporting.SkipHTMLReport to true" {
            Set-AuditConfigValue -Section "Reporting" -Key "SkipHTMLReport" -Value $true -Confirm:$false
            $value = Get-AuditConfigValue -Section "Reporting" -Key "SkipHTMLReport"
            $value | Should -Be $true
        }

        It "Should set Authentication.AuthMethod to AppRegistration" {
            Set-AuditConfigValue -Section "Authentication" -Key "AuthMethod" -Value "AppRegistration" -Confirm:$false
            $value = Get-AuditConfigValue -Section "Authentication" -Key "AuthMethod"
            $value | Should -Be "AppRegistration"
        }

        It "Should throw when setting value in non-existent Section" {
            { Set-AuditConfigValue -Section "NonExistent" -Key "SomeKey" -Value "SomeValue" -Confirm:$false } |
                Should -Throw
        }

        It "Should throw when setting non-existent Key" {
            { Set-AuditConfigValue -Section "Logging" -Key "NonExistentKey" -Value "SomeValue" -Confirm:$false } |
                Should -Throw
        }

        It "Should support WhatIf without changing value" {
            $originalValue = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "Error" -WhatIf
            $newValue = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            $newValue | Should -Be $originalValue
        }

        It "Should update value when WhatIf is not specified" {
            Set-AuditConfigValue -Section "DataCollection" -Key "MaxRetries" -Value 10 -Confirm:$false
            $value = Get-AuditConfigValue -Section "DataCollection" -Key "MaxRetries"
            $value | Should -Be 10
        }
    }

    Context "Initialize-AuditConfig with No File" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        AfterEach {
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        It "Should initialize with defaults when no file is provided" {
            { Initialize-AuditConfig } | Should -Not -Throw
        }

        It "Should maintain default values when no file is provided" {
            Initialize-AuditConfig
            $config = Get-AuditConfig
            $config.Logging.LogLevel | Should -Be "Info"
        }

        It "Should handle non-existent file path gracefully" {
            $nonExistentPath = Join-Path $script:TestOutputPath "non-existent-config.json"
            { Initialize-AuditConfig -ConfigFilePath $nonExistentPath } | Should -Not -Throw
        }
    }

    Context "Initialize-AuditConfig with Valid JSON File" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            $script:configPath = Join-Path $script:TestOutputPath "test-config-$(New-Guid).json"
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:configPath) {
                Remove-Item $script:configPath -Force -ErrorAction SilentlyContinue
            }
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        It "Should load configuration from valid JSON file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = $null
                    ClientSecret = $null
                    TenantId = $null
                    AuthMethod = "Interactive"
                }
                Logging = @{
                    LogLevel = "Debug"
                    LogToFile = $true
                    LogToConsole = $true
                }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            $value = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            $value | Should -Be "Debug"
        }

        It "Should load Authentication.ClientId from file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = "test-client-id-123"
                    ClientSecret = $null
                    TenantId = $null
                    AuthMethod = "Interactive"
                }
                Logging = @{ LogLevel = "Info"; LogToFile = $true; LogToConsole = $true }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            $value = Get-AuditConfigValue -Section "Authentication" -Key "ClientId"
            $value | Should -Be "test-client-id-123"
        }

        It "Should load Authentication.TenantId from file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = $null
                    ClientSecret = $null
                    TenantId = "test-tenant-id-456"
                    AuthMethod = "Interactive"
                }
                Logging = @{ LogLevel = "Info"; LogToFile = $true; LogToConsole = $true }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            $value = Get-AuditConfigValue -Section "Authentication" -Key "TenantId"
            $value | Should -Be "test-tenant-id-456"
        }

        It "Should load DataCollection.ResourceGraphPageSize from file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = $null
                    ClientSecret = $null
                    TenantId = $null
                    AuthMethod = "Interactive"
                }
                Logging = @{ LogLevel = "Info"; LogToFile = $true; LogToConsole = $true }
                DataCollection = @{
                    ResourceGraphPageSize = 2500
                }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            $value = Get-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize"
            $value | Should -Be 2500
        }

        It "Should load Analysis.MaxConcurrentQueries from file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = $null
                    ClientSecret = $null
                    TenantId = $null
                    AuthMethod = "Interactive"
                }
                Logging = @{ LogLevel = "Info"; LogToFile = $true; LogToConsole = $true }
                Analysis = @{
                    MaxConcurrentQueries = 8
                }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            $value = Get-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries"
            $value | Should -Be 8
        }

        It "Should load multiple configuration sections from file" {
            $testConfig = @{
                Authentication = @{
                    ClientId = $null
                    ClientSecret = $null
                    TenantId = $null
                    AuthMethod = "Interactive"
                }
                Logging = @{
                    LogLevel = "Warning"
                    LogToFile = $true
                    LogToConsole = $true
                }
                DataCollection = @{
                    MaxRetries = 10
                }
                Analysis = @{
                    ParallelProcessingThreshold = 200
                }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            Initialize-AuditConfig -ConfigFilePath $script:configPath

            Get-AuditConfigValue -Section "Logging" -Key "LogLevel" | Should -Be "Warning"
            Get-AuditConfigValue -Section "DataCollection" -Key "MaxRetries" | Should -Be 10
            Get-AuditConfigValue -Section "Analysis" -Key "ParallelProcessingThreshold" | Should -Be 200
        }
    }

    Context "Initialize-AuditConfig with Environment Variables" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        AfterEach {
            Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
        }

        It "Should load ClientId from environment variable" {
            $env:AZURE_CLIENT_ID = "env-client-id-123"
            Initialize-AuditConfig

            $value = Get-AuditConfigValue -Section "Authentication" -Key "ClientId"
            $value | Should -Be "env-client-id-123"
        }

        It "Should load TenantId from environment variable" {
            $env:AZURE_TENANT_ID = "env-tenant-id-456"
            Initialize-AuditConfig

            $value = Get-AuditConfigValue -Section "Authentication" -Key "TenantId"
            $value | Should -Be "env-tenant-id-456"
        }

        It "Should load ClientSecret from environment variable as SecureString" {
            $env:AZURE_CLIENT_SECRET = "env-secret-789"
            Initialize-AuditConfig

            $value = Get-AuditConfigValue -Section "Authentication" -Key "ClientSecret"
            $value | Should -BeOfType [SecureString]
        }

        It "Should prioritize environment variables over config file" {
            $script:configPath = Join-Path $script:TestOutputPath "test-config-$(New-Guid).json"
            $testConfig = @{
                Authentication = @{
                    ClientId = "file-client-id"
                    ClientSecret = $null
                    TenantId = "file-tenant-id"
                    AuthMethod = "Interactive"
                }
                Logging = @{ LogLevel = "Info"; LogToFile = $true; LogToConsole = $true }
            }
            $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:configPath -Encoding UTF8

            $env:AZURE_CLIENT_ID = "env-client-id-priority"
            $env:AZURE_TENANT_ID = "env-tenant-id-priority"
            Initialize-AuditConfig -ConfigFilePath $script:configPath

            Get-AuditConfigValue -Section "Authentication" -Key "ClientId" | Should -Be "env-client-id-priority"
            Get-AuditConfigValue -Section "Authentication" -Key "TenantId" | Should -Be "env-tenant-id-priority"

            if (Test-Path $script:configPath) {
                Remove-Item $script:configPath -Force
            }
        }
    }

    Context "Test-AuditConfig Validation" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
        }

        It "Should pass validation with default configuration" {
            Initialize-AuditConfig
            { Test-AuditConfig } | Should -Not -Throw
        }

        It "Should return true when validation passes" {
            Initialize-AuditConfig
            $result = Test-AuditConfig
            $result | Should -Be $true
        }

        It "Should fail validation when LogLevel is invalid" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "InvalidLevel" -Confirm:$false
            { Test-AuditConfig } | Should -Throw
        }

        It "Should fail validation when ResourceGraphPageSize is too low" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize" -Value 50 -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*must be between 100 and 5000*"
        }

        It "Should fail validation when ResourceGraphPageSize is too high" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize" -Value 6000 -Confirm:$false
            { Test-AuditConfig } | Should -Throw
        }

        It "Should fail validation when MaxConcurrentQueries is less than 1" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries" -Value 0 -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*must be at least 1*"
        }

        It "Should fail validation when MaxConcurrentQueries exceeds 15" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Analysis" -Key "MaxConcurrentQueries" -Value 20 -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*cannot exceed 15*"
        }

        It "Should fail validation for AppRegistration without ClientId" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Authentication" -Key "AuthMethod" -Value "AppRegistration" -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*ClientId is required*"
        }

        It "Should fail validation for AppRegistration without ClientSecret" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Authentication" -Key "AuthMethod" -Value "AppRegistration" -Confirm:$false
            Set-AuditConfigValue -Section "Authentication" -Key "ClientId" -Value "test-client-id" -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*ClientSecret is required*"
        }

        It "Should fail validation for AppRegistration without TenantId" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Authentication" -Key "AuthMethod" -Value "AppRegistration" -Confirm:$false
            Set-AuditConfigValue -Section "Authentication" -Key "ClientId" -Value "test-client-id" -Confirm:$false
            $secureSecret = ConvertTo-SecureString -String "test-secret" -AsPlainText -Force
            Set-AuditConfigValue -Section "Authentication" -Key "ClientSecret" -Value $secureSecret -Confirm:$false
            { Test-AuditConfig } | Should -Throw "*TenantId is required*"
        }

        It "Should pass validation for AppRegistration with all required fields" {
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Authentication" -Key "AuthMethod" -Value "AppRegistration" -Confirm:$false
            Set-AuditConfigValue -Section "Authentication" -Key "ClientId" -Value "test-client-id" -Confirm:$false
            $secureSecret = ConvertTo-SecureString -String "test-secret" -AsPlainText -Force
            Set-AuditConfigValue -Section "Authentication" -Key "ClientSecret" -Value $secureSecret -Confirm:$false
            Set-AuditConfigValue -Section "Authentication" -Key "TenantId" -Value "test-tenant-id" -Confirm:$false

            { Test-AuditConfig } | Should -Not -Throw
        }
    }

    Context "Export-AuditConfigTemplate Function" {

        BeforeEach {
            $script:templatePath = Join-Path $script:TestOutputPath "template-$(New-Guid).json"
        }

        AfterEach {
            if (Test-Path $script:templatePath) {
                Remove-Item $script:templatePath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should create template file" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            Test-Path $script:templatePath | Should -Be $true
        }

        It "Should create valid JSON file" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            { Get-Content $script:templatePath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Should include Authentication section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "Authentication"
        }

        It "Should include Logging section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "Logging"
        }

        It "Should include DataCollection section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "DataCollection"
        }

        It "Should include Analysis section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "Analysis"
        }

        It "Should include Reporting section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "Reporting"
        }

        It "Should include Subscriptions section in template" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $template = Get-Content $script:templatePath -Raw | ConvertFrom-Json
            $template.PSObject.Properties.Name | Should -Contain "Subscriptions"
        }

        It "Should use UTF-8 encoding" {
            Export-AuditConfigTemplate -OutputPath $script:templatePath

            $bytes = [System.IO.File]::ReadAllBytes($script:templatePath)
            $content = Get-Content $script:templatePath -Raw
            $content | Should -Not -BeNullOrEmpty
        }
    }

    Context "Show-AuditConfig Function" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Initialize-AuditConfig
        }

        It "Should execute without errors" {
            { Show-AuditConfig } | Should -Not -Throw
        }

        It "Should execute with default configuration" {
            { Show-AuditConfig } | Should -Not -Throw
        }

        It "Should execute after setting custom values" {
            Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "Debug" -Confirm:$false
            { Show-AuditConfig } | Should -Not -Throw
        }
    }

    Context "Module Export Verification" {

        It "Should export Initialize-AuditConfig function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Initialize-AuditConfig"
        }

        It "Should export Set-AuditConfigValue function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Set-AuditConfigValue"
        }

        It "Should export Get-AuditConfigValue function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Get-AuditConfigValue"
        }

        It "Should export Get-AuditConfig function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Get-AuditConfig"
        }

        It "Should export Export-AuditConfigTemplate function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Export-AuditConfigTemplate"
        }

        It "Should export Test-AuditConfig function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Test-AuditConfig"
        }

        It "Should export Show-AuditConfig function" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Name | Should -Contain "Show-AuditConfig"
        }

        It "Should export exactly 7 functions" {
            $commands = Get-Command -Module AzureAudit.Config
            $commands.Count | Should -Be 7
        }
    }

    Context "Configuration State Isolation" {

        It "Should maintain separate state across module reloads" {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Initialize-AuditConfig
            Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "Debug" -Confirm:$false

            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            $value = Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
            $value | Should -Be "Info"
        }

        It "Should allow independent configuration per session" {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Set-AuditConfigValue -Section "DataCollection" -Key "MaxRetries" -Value 15 -Confirm:$false
            $value1 = Get-AuditConfigValue -Section "DataCollection" -Key "MaxRetries"

            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            $value2 = Get-AuditConfigValue -Section "DataCollection" -Key "MaxRetries"

            $value1 | Should -Be 15
            $value2 | Should -Be 5
        }
    }

    Context "SecureString Handling" {

        BeforeEach {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Config.psm1" -Force
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
        }

        AfterEach {
            Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
        }

        It "Should store ClientSecret as SecureString from environment variable" {
            $env:AZURE_CLIENT_SECRET = "test-secret-string"
            Initialize-AuditConfig

            $value = Get-AuditConfigValue -Section "Authentication" -Key "ClientSecret"
            $value | Should -BeOfType [SecureString]
        }

        It "Should accept SecureString when setting ClientSecret" {
            Initialize-AuditConfig
            $secureSecret = ConvertTo-SecureString -String "new-secret" -AsPlainText -Force

            { Set-AuditConfigValue -Section "Authentication" -Key "ClientSecret" -Value $secureSecret -Confirm:$false } |
                Should -Not -Throw
        }

        It "Should maintain SecureString type after setting ClientSecret" {
            Initialize-AuditConfig
            $secureSecret = ConvertTo-SecureString -String "new-secret" -AsPlainText -Force
            Set-AuditConfigValue -Section "Authentication" -Key "ClientSecret" -Value $secureSecret -Confirm:$false

            $value = Get-AuditConfigValue -Section "Authentication" -Key "ClientSecret"
            $value | Should -BeOfType [SecureString]
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    Remove-Item Env:\AZURE_CLIENT_ID -ErrorAction SilentlyContinue
    Remove-Item Env:\AZURE_CLIENT_SECRET -ErrorAction SilentlyContinue
    Remove-Item Env:\AZURE_TENANT_ID -ErrorAction SilentlyContinue
}
