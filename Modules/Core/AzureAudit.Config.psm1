Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AuditConfig = @{
    Authentication = @{
        ClientId = $null
        ClientSecret = [SecureString]$null
        TenantId = $null
        AuthMethod = "Interactive"
    }
    Logging = @{
        LogLevel = "Info"
        LogFilePath = $null
        LogToFile = $true
        LogToConsole = $true
    }
    DataCollection = @{
        ResourceGraphPageSize = 1000
        MaxRetries = 5
        BaseDelaySeconds = 2
    }
    Analysis = @{
        MaxConcurrentQueries = 5
        ParallelProcessingThreshold = 100
    }
    Reporting = @{
        OutputPath = ".\AuditReports"
        SkipHTMLReport = $false
        IncludeTimestamp = $true
        HTMLIssueLimit = @{
            Critical = 100
            High = 50
            Medium = 50
        }
        Visualization = @{
            EnableNetworkGraphs = $true
            Formats = @("JSON", "DOT", "SVG", "PNG", "HTML", "Mermaid", "DrawIO")
            GraphvizPath = "dot"
            IncludeTimestamp = $true
            HighlightIssues = $true
            ColorScheme = "Azure"
            GroupBySubscription = $true
        }
    }
    Subscriptions = @{
        SubscriptionIds = @()
        IncludeDisabled = $false
    }
}

function Initialize-AuditConfig {
    <#
    .SYNOPSIS
    Initializes audit configuration from file and environment variables.

    .DESCRIPTION
    Loads audit configuration settings from a JSON file and overrides with environment
    variables if present. Handles secure storage of client secrets using encrypted
    strings. Creates the default configuration structure if no file is provided.
    Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    take precedence over config file values.

    .PARAMETER ConfigFilePath
    Optional path to JSON configuration file. If not provided or file does not exist,
    uses default configuration settings.

    .EXAMPLE
    Initialize-AuditConfig
    Initializes with default configuration and environment variables

    .EXAMPLE
    Initialize-AuditConfig -ConfigFilePath "C:\Config\audit-config.json"
    Loads configuration from specified JSON file and overrides with environment variables

    .NOTES
    Client secrets should be stored as environment variables for security.
    Config file supports encrypted secrets with "encrypted:" prefix.
    Environment variables always override configuration file values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigFilePath
    )

    if ($ConfigFilePath -and (Test-Path $ConfigFilePath)) {
        Write-Verbose "Loading configuration from: $ConfigFilePath"

        $configData = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json

        if ($configData.Authentication) {
            if ($configData.Authentication.ClientId) {
                $script:AuditConfig.Authentication.ClientId = $configData.Authentication.ClientId
            }
            if ($configData.Authentication.ClientSecret) {
                if ($configData.Authentication.ClientSecret.StartsWith("encrypted:")) {
                    $encryptedString = $configData.Authentication.ClientSecret.Substring(10)
                    $script:AuditConfig.Authentication.ClientSecret = ConvertTo-SecureString -String $encryptedString
                }
                else {
                    $plainSecret = $configData.Authentication.ClientSecret
                    $secureSecret = ConvertTo-SecureString -String $plainSecret -AsPlainText -Force
                    $encryptedStandardString = ConvertFrom-SecureString -SecureString $secureSecret

                    Write-Warning "ClientSecret stored as plaintext. Next time use encrypted format in config:"
                    Write-Warning "`"ClientSecret`": `"encrypted:$encryptedStandardString`""

                    $script:AuditConfig.Authentication.ClientSecret = $secureSecret
                }
            }
            if ($configData.Authentication.TenantId) {
                $script:AuditConfig.Authentication.TenantId = $configData.Authentication.TenantId
            }
            if ($configData.Authentication.AuthMethod) {
                $script:AuditConfig.Authentication.AuthMethod = $configData.Authentication.AuthMethod
            }
        }

        if ($configData.PSObject.Properties['Logging']) {
            if ($configData.Logging.PSObject.Properties['LogLevel']) {
                $script:AuditConfig.Logging.LogLevel = $configData.Logging.LogLevel
            }
            if ($configData.Logging.PSObject.Properties['LogToFile']) {
                $script:AuditConfig.Logging.LogToFile = $configData.Logging.LogToFile
            }
            if ($configData.Logging.PSObject.Properties['LogToConsole']) {
                $script:AuditConfig.Logging.LogToConsole = $configData.Logging.LogToConsole
            }
        }

        if ($configData.PSObject.Properties['DataCollection']) {
            if ($configData.DataCollection.PSObject.Properties['ResourceGraphPageSize']) {
                $script:AuditConfig.DataCollection.ResourceGraphPageSize = $configData.DataCollection.ResourceGraphPageSize
            }
            if ($configData.DataCollection.PSObject.Properties['MaxRetries']) {
                $script:AuditConfig.DataCollection.MaxRetries = $configData.DataCollection.MaxRetries
            }
            if ($configData.DataCollection.PSObject.Properties['BaseDelaySeconds']) {
                $script:AuditConfig.DataCollection.BaseDelaySeconds = $configData.DataCollection.BaseDelaySeconds
            }
        }

        if ($configData.PSObject.Properties['Analysis']) {
            if ($configData.Analysis.PSObject.Properties['MaxConcurrentQueries']) {
                $script:AuditConfig.Analysis.MaxConcurrentQueries = $configData.Analysis.MaxConcurrentQueries
            }
            if ($configData.Analysis.PSObject.Properties['ParallelProcessingThreshold']) {
                $script:AuditConfig.Analysis.ParallelProcessingThreshold = $configData.Analysis.ParallelProcessingThreshold
            }
        }

        if ($configData.PSObject.Properties['Reporting']) {
            if ($configData.Reporting.PSObject.Properties['OutputPath']) {
                $script:AuditConfig.Reporting.OutputPath = $configData.Reporting.OutputPath
            }
            if ($configData.Reporting.PSObject.Properties['SkipHTMLReport']) {
                $script:AuditConfig.Reporting.SkipHTMLReport = $configData.Reporting.SkipHTMLReport
            }
            if ($configData.Reporting.PSObject.Properties['IncludeTimestamp']) {
                $script:AuditConfig.Reporting.IncludeTimestamp = $configData.Reporting.IncludeTimestamp
            }
            if ($configData.Reporting.PSObject.Properties['Visualization']) {
                if ($configData.Reporting.Visualization.PSObject.Properties['EnableNetworkGraphs']) {
                    $script:AuditConfig.Reporting.Visualization.EnableNetworkGraphs = $configData.Reporting.Visualization.EnableNetworkGraphs
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['Formats']) {
                    $script:AuditConfig.Reporting.Visualization.Formats = $configData.Reporting.Visualization.Formats
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['GraphvizPath']) {
                    $script:AuditConfig.Reporting.Visualization.GraphvizPath = $configData.Reporting.Visualization.GraphvizPath
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['IncludeTimestamp']) {
                    $script:AuditConfig.Reporting.Visualization.IncludeTimestamp = $configData.Reporting.Visualization.IncludeTimestamp
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['HighlightIssues']) {
                    $script:AuditConfig.Reporting.Visualization.HighlightIssues = $configData.Reporting.Visualization.HighlightIssues
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['ColorScheme']) {
                    $script:AuditConfig.Reporting.Visualization.ColorScheme = $configData.Reporting.Visualization.ColorScheme
                }
                if ($configData.Reporting.Visualization.PSObject.Properties['GroupBySubscription']) {
                    $script:AuditConfig.Reporting.Visualization.GroupBySubscription = $configData.Reporting.Visualization.GroupBySubscription
                }
            }
        }

        if ($configData.PSObject.Properties['Subscriptions']) {
            if ($configData.Subscriptions.PSObject.Properties['SubscriptionIds']) {
                $script:AuditConfig.Subscriptions.SubscriptionIds = $configData.Subscriptions.SubscriptionIds
            }
        }

        Write-Verbose "Configuration loaded successfully"
    }
    else {
        Write-Verbose "No configuration file provided or file not found. Using defaults."
    }

    if ($env:AZURE_CLIENT_ID) {
        $script:AuditConfig.Authentication.ClientId = $env:AZURE_CLIENT_ID
        Write-Verbose "Using ClientId from environment variable AZURE_CLIENT_ID"
    }

    if ($env:AZURE_CLIENT_SECRET) {
        $script:AuditConfig.Authentication.ClientSecret = ConvertTo-SecureString -String $env:AZURE_CLIENT_SECRET -AsPlainText -Force
        Write-Verbose "Using ClientSecret from environment variable AZURE_CLIENT_SECRET"
    }

    if ($env:AZURE_TENANT_ID) {
        $script:AuditConfig.Authentication.TenantId = $env:AZURE_TENANT_ID
        Write-Verbose "Using TenantId from environment variable AZURE_TENANT_ID"
    }
}

function Set-AuditConfigValue {
    <#
    .SYNOPSIS
    Updates a specific configuration value in the audit configuration.

    .DESCRIPTION
    Modifies a configuration value within a specified section of the audit configuration
    hashtable. Validates that the section and key exist before updating. Supports
    WhatIf and Confirm for safe configuration changes.

    .PARAMETER Section
    Configuration section to modify (Authentication, Logging, DataCollection, Analysis, Reporting, or Subscriptions)

    .PARAMETER Key
    Configuration key within the section to update

    .PARAMETER Value
    New value to assign to the configuration key

    .EXAMPLE
    Set-AuditConfigValue -Section "Logging" -Key "LogLevel" -Value "Debug"
    Sets the log level to Debug for more detailed logging

    .EXAMPLE
    Set-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize" -Value 500
    Changes the page size for Resource Graph queries to 500

    .NOTES
    Throws an error if the section or key does not exist in the configuration.
    Use Get-AuditConfig to view current configuration structure.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Authentication", "Logging", "DataCollection", "Analysis", "Reporting", "Subscriptions")]
        [string]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($script:AuditConfig.ContainsKey($Section)) {
        if ($script:AuditConfig[$Section].ContainsKey($Key)) {
            if ($PSCmdlet.ShouldProcess("$Section.$Key", "Set configuration value to '$Value'")) {
                $script:AuditConfig[$Section][$Key] = $Value
                Write-Verbose "Set $Section.$Key = $Value"
            }
        }
        else {
            throw "Key '$Key' not found in section '$Section'"
        }
    }
    else {
        throw "Section '$Section' not found in configuration"
    }
}

function Get-AuditConfigValue {
    <#
    .SYNOPSIS
    Retrieves a specific configuration value from the audit configuration.

    .DESCRIPTION
    Returns the value of a specified configuration key within a section of the audit
    configuration hashtable. Throws an error if the section or key does not exist.

    .PARAMETER Section
    Configuration section to query (Authentication, Logging, DataCollection, Analysis, Reporting, or Subscriptions)

    .PARAMETER Key
    Configuration key within the section to retrieve

    .EXAMPLE
    Get-AuditConfigValue -Section "Logging" -Key "LogLevel"
    Returns the current log level setting (e.g., "Info")

    .EXAMPLE
    $pageSize = Get-AuditConfigValue -Section "DataCollection" -Key "ResourceGraphPageSize"
    Retrieves the Resource Graph page size and stores it in a variable

    .OUTPUTS
    System.Object
    Returns the configuration value which can be string, integer, boolean, array, or hashtable

    .NOTES
    Throws an error if the section or key does not exist in the configuration.
    Use Get-AuditConfig to retrieve the entire configuration structure.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Authentication", "Logging", "DataCollection", "Analysis", "Reporting", "Subscriptions")]
        [string]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    if ($script:AuditConfig.ContainsKey($Section)) {
        if ($script:AuditConfig[$Section].ContainsKey($Key)) {
            return $script:AuditConfig[$Section][$Key]
        }
        else {
            throw "Key '$Key' not found in section '$Section'"
        }
    }
    else {
        throw "Section '$Section' not found in configuration"
    }
}

function Get-AuditConfig {
    <#
    .SYNOPSIS
    Retrieves the complete audit configuration object.

    .DESCRIPTION
    Returns the entire audit configuration hashtable containing all sections:
    Authentication, Logging, DataCollection, Analysis, Reporting, and Subscriptions.
    Use this to view the full configuration structure or pass to other functions.

    .EXAMPLE
    $config = Get-AuditConfig
    Retrieves the complete configuration hashtable

    .EXAMPLE
    Get-AuditConfig | ConvertTo-Json -Depth 10
    Displays the complete configuration in JSON format

    .OUTPUTS
    System.Collections.Hashtable
    Returns the complete audit configuration hashtable with all sections and settings

    .NOTES
    The returned hashtable is a reference to the script-scope configuration.
    Modifications to the returned object will affect the active configuration.
    Use Set-AuditConfigValue for safe configuration updates.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:AuditConfig
}

function Export-AuditConfigTemplate {
    <#
    .SYNOPSIS
    Exports a configuration template JSON file with default values.

    .DESCRIPTION
    Creates a template JSON configuration file with default settings and structure.
    The template includes all configuration sections with sample values. Provides
    security guidance for handling client secrets. Use this template as a starting
    point for creating custom audit configurations.

    .PARAMETER OutputPath
    Full path where the configuration template JSON file will be created

    .EXAMPLE
    Export-AuditConfigTemplate -OutputPath "C:\Config\audit-template.json"
    Creates a new configuration template file at the specified location

    .EXAMPLE
    Export-AuditConfigTemplate -OutputPath ".\my-audit-config.json"
    Creates a template in the current directory

    .NOTES
    The exported template includes security warnings about storing secrets.
    Always use environment variables for client secrets in production.
    Never commit configuration files with secrets to version control.
    The template file is created with UTF-8 encoding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $template = @{
        Authentication = @{
            ClientId = "your-client-id-here"
            TenantId = "your-tenant-id-here"
            AuthMethod = "AppRegistration"
        }
        Logging = @{
            LogLevel = "Info"
            LogToFile = $true
            LogToConsole = $true
        }
        DataCollection = @{
            ResourceGraphPageSize = 1000
            MaxRetries = 5
            BaseDelaySeconds = 2
        }
        Analysis = @{
            MaxConcurrentQueries = 5
            ParallelProcessingThreshold = 100
        }
        Reporting = @{
            OutputPath = ".\AuditReports"
            SkipHTMLReport = $false
        }
        Subscriptions = @{
            SubscriptionIds = @()
        }
    }

    $template | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Information "Configuration template exported to: $OutputPath" -InformationAction Continue -Tags @("Success")
    Write-Information "" -InformationAction Continue -Tags @("Info")
    Write-Information "SECURITY BEST PRACTICES:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  1. RECOMMENDED: Store ClientSecret in environment variable AZURE_CLIENT_SECRET" -InformationAction Continue -Tags @("Warning")
    Write-Information "     Example: `$env:AZURE_CLIENT_SECRET = 'your-secret-here'" -InformationAction Continue -Tags @("Warning")
    Write-Information "" -InformationAction Continue -Tags @("Info")
    Write-Information "  2. ALTERNATIVE (NOT RECOMMENDED): Add ClientSecret to config file" -InformationAction Continue -Tags @("Warning")
    Write-Information "     This is ONLY acceptable for development/testing environments" -InformationAction Continue -Tags @("Warning")
    Write-Information "     Add: `"ClientSecret`": `"your-secret-here`" under Authentication section" -InformationAction Continue -Tags @("Warning")
    Write-Information "     WARNING: Never commit config files with secrets to version control!" -InformationAction Continue -Tags @("Error")
}

function Test-AuditConfig {
    <#
    .SYNOPSIS
    Validates the current audit configuration for correctness and completeness.

    .DESCRIPTION
    Performs comprehensive validation of the audit configuration including:
    - Required authentication settings for App Registration method
    - Valid log level values
    - Resource Graph page size within Azure limits (100-5000)
    - Concurrent query limits within safe ranges (1-10)
    Throws an error with detailed messages if validation fails.

    .EXAMPLE
    Test-AuditConfig
    Validates the current configuration and returns $true if valid

    .EXAMPLE
    if (Test-AuditConfig) { Start-AzureAudit }
    Validates configuration before starting an audit

    .OUTPUTS
    System.Boolean
    Returns $true if configuration is valid, throws error if invalid

    .NOTES
    Always run this before executing audits to ensure proper configuration.
    Validation errors provide specific guidance on what needs to be corrected.
    App Registration authentication requires ClientId, ClientSecret, and TenantId.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $validationErrors = @()

    if ($script:AuditConfig.Authentication.AuthMethod -eq "AppRegistration") {
        if ([string]::IsNullOrEmpty($script:AuditConfig.Authentication.ClientId)) {
            $validationErrors += "Authentication.ClientId is required for AppRegistration auth"
        }
        if ($null -eq $script:AuditConfig.Authentication.ClientSecret -or $script:AuditConfig.Authentication.ClientSecret.Length -eq 0) {
            $validationErrors += "Authentication.ClientSecret is required for AppRegistration auth (set via environment variable AZURE_CLIENT_SECRET)"
        }
        if ([string]::IsNullOrEmpty($script:AuditConfig.Authentication.TenantId)) {
            $validationErrors += "Authentication.TenantId is required for AppRegistration auth"
        }
    }

    $validLogLevels = @("Info", "Warning", "Error", "Debug")
    if ($script:AuditConfig.Logging.LogLevel -notin $validLogLevels) {
        $validationErrors += "Logging.LogLevel must be one of: $($validLogLevels -join ', ')"
    }

    if ($script:AuditConfig.DataCollection.ResourceGraphPageSize -lt 100 -or
        $script:AuditConfig.DataCollection.ResourceGraphPageSize -gt 5000) {
        $validationErrors += "DataCollection.ResourceGraphPageSize must be between 100 and 5000"
    }

    if ($script:AuditConfig.Analysis.MaxConcurrentQueries -lt 1) {
        $validationErrors += "Analysis.MaxConcurrentQueries must be at least 1"
    }

    if ($script:AuditConfig.Analysis.MaxConcurrentQueries -gt 15) {
        $validationErrors += "Analysis.MaxConcurrentQueries cannot exceed 15 (Azure Resource Graph concurrent query limit)"
    }

    if ($script:AuditConfig.DataCollection.ResourceGraphPageSize -gt 5000) {
        $validationErrors += "DataCollection.ResourceGraphPageSize cannot exceed 5000 (Azure Resource Graph page size limit)"
    }

    if ($validationErrors.Count -gt 0) {
        throw "Configuration validation failed:`n" + ($validationErrors -join "`n")
    }

    Write-Verbose "Configuration validation passed"
    return $true
}

function Show-AuditConfig {
    <#
    .SYNOPSIS
    Displays the current audit configuration in a formatted view.

    .DESCRIPTION
    Outputs a human-readable view of the entire audit configuration to the console.
    Sensitive values like ClientId, ClientSecret, and TenantId are masked for security.
    Shows all configuration sections including Authentication, Logging, DataCollection,
    Analysis, Reporting, and Subscriptions with their current values.

    .EXAMPLE
    Show-AuditConfig
    Displays the complete audit configuration with masked sensitive values

    .EXAMPLE
    Show-AuditConfig -Verbose
    Displays the configuration with verbose output enabled

    .NOTES
    Sensitive authentication values are displayed as "***configured***" or "not set".
    Use Get-AuditConfig to retrieve the actual configuration object programmatically.
    Output uses Write-Information to ensure visibility regardless of preference variables.
    #>
    [CmdletBinding()]
    param()

    Write-Information "`nCurrent Audit Configuration:" -InformationAction Continue -Tags @("Info")
    Write-Information "============================`n" -InformationAction Continue -Tags @("Info")

    Write-Information "Authentication:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  AuthMethod: $($script:AuditConfig.Authentication.AuthMethod)" -InformationAction Continue -Tags @("Info")
    Write-Information "  ClientId: $(if($script:AuditConfig.Authentication.ClientId){'***configured***'}else{'not set'})" -InformationAction Continue -Tags @("Info")
    Write-Information "  ClientSecret: $(if($script:AuditConfig.Authentication.ClientSecret){'***configured***'}else{'not set'})" -InformationAction Continue -Tags @("Info")
    Write-Information "  TenantId: $(if($script:AuditConfig.Authentication.TenantId){'***configured***'}else{'not set'})" -InformationAction Continue -Tags @("Info")

    Write-Information "`nLogging:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  LogLevel: $($script:AuditConfig.Logging.LogLevel)" -InformationAction Continue -Tags @("Info")
    Write-Information "  LogToFile: $($script:AuditConfig.Logging.LogToFile)" -InformationAction Continue -Tags @("Info")
    Write-Information "  LogToConsole: $($script:AuditConfig.Logging.LogToConsole)" -InformationAction Continue -Tags @("Info")

    Write-Information "`nData Collection:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  ResourceGraphPageSize: $($script:AuditConfig.DataCollection.ResourceGraphPageSize)" -InformationAction Continue -Tags @("Info")
    Write-Information "  MaxRetries: $($script:AuditConfig.DataCollection.MaxRetries)" -InformationAction Continue -Tags @("Info")
    Write-Information "  BaseDelaySeconds: $($script:AuditConfig.DataCollection.BaseDelaySeconds)" -InformationAction Continue -Tags @("Info")

    Write-Information "`nAnalysis:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  MaxConcurrentQueries: $($script:AuditConfig.Analysis.MaxConcurrentQueries)" -InformationAction Continue -Tags @("Info")
    Write-Information "  ParallelProcessingThreshold: $($script:AuditConfig.Analysis.ParallelProcessingThreshold)" -InformationAction Continue -Tags @("Info")

    Write-Information "`nReporting:" -InformationAction Continue -Tags @("Warning")
    Write-Information "  OutputPath: $($script:AuditConfig.Reporting.OutputPath)" -InformationAction Continue -Tags @("Info")
    Write-Information "  SkipHTMLReport: $($script:AuditConfig.Reporting.SkipHTMLReport)" -InformationAction Continue -Tags @("Info")

    Write-Information "`nSubscriptions:" -InformationAction Continue -Tags @("Warning")
    if ($script:AuditConfig.Subscriptions.SubscriptionIds.Count -gt 0) {
        Write-Information "  SubscriptionIds: $($script:AuditConfig.Subscriptions.SubscriptionIds.Count) configured" -InformationAction Continue -Tags @("Info")
        foreach ($subId in $script:AuditConfig.Subscriptions.SubscriptionIds) {
            Write-Information "    - $subId" -InformationAction Continue -Tags @("Info")
        }
    }
    else {
        Write-Information "  SubscriptionIds: All accessible subscriptions" -InformationAction Continue -Tags @("Info")
    }
    Write-Information "" -InformationAction Continue -Tags @("Info")
}

Export-ModuleMember -Function Initialize-AuditConfig, Set-AuditConfigValue, Get-AuditConfigValue, Get-AuditConfig, Export-AuditConfigTemplate, Test-AuditConfig, Show-AuditConfig
