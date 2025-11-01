Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogFilePath = $null
$script:LogLevelValue = 3

function Initialize-AuditLogging {
    <#
    .SYNOPSIS
    Initializes audit logging system with file path and log level.

    .DESCRIPTION
    Configures the audit logging system by setting the log file path and minimum
    log level for output filtering. Must be called before Write-AuditLog to enable
    file logging.

    .PARAMETER LogFilePath
    Full path to the log file where audit messages will be written

    .PARAMETER LogLevel
    Minimum log level to write (Error, Warning, Info, Debug). Default is Info.

    .EXAMPLE
    Initialize-AuditLogging -LogFilePath "C:\Logs\audit.log" -LogLevel "Info"

    .NOTES
    Log levels filter messages: Error (1) < Warning (2) < Info (3) < Debug (4)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$LogLevel = "Info"
    )

    $script:LogFilePath = $LogFilePath
    $script:LogLevelValue = @{ "Error" = 1; "Warning" = 2; "Info" = 3; "Debug" = 4 }[$LogLevel]

    Write-AuditLog "Logging initialized: $LogFilePath" -Type Info
}

function Write-AuditLog {
    <#
    .SYNOPSIS
    Writes a message to the audit log and console.

    .DESCRIPTION
    Logs a timestamped message to both the configured log file and console output
    (unless NoConsole is specified). Messages are filtered by the configured log level.
    Console output uses Write-Information with appropriate tags.

    .PARAMETER Message
    The message text to log

    .PARAMETER Type
    Message type/severity (Info, Success, Warning, Error, Debug, Progress). Default is Info.

    .PARAMETER NoConsole
    If specified, suppresses console output and only writes to log file

    .EXAMPLE
    Write-AuditLog "Starting network scan" -Type Progress

    .EXAMPLE
    Write-AuditLog "Critical issue detected" -Type Error

    .NOTES
    Requires Initialize-AuditLogging to be called first for file logging
    Console output uses Write-Information which requires -InformationAction Continue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug", "Progress")]
        [string]$Type = "Info",

        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )

    $logLevelMap = @{
        "Error" = 1
        "Warning" = 2
        "Success" = 3
        "Info" = 3
        "Progress" = 3
        "Debug" = 4
    }

    if ($logLevelMap[$Type] -gt $script:LogLevelValue) {
        return
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Type] $Message"

    if ($script:LogFilePath) {
        Add-Content -Path $script:LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
    }

    if (!$NoConsole) {
        $prefix = switch ($Type) {
            "Info" { "[INFO]" }
            "Success" { "[OK]" }
            "Warning" { "[WARN]" }
            "Error" { "[ERROR]" }
            "Progress" { "[PROGRESS]" }
            "Debug" { "[DEBUG]" }
            default { "[INFO]" }
        }

        $tags = switch ($Type) {
            "Info" { @("Info") }
            "Success" { @("Success") }
            "Warning" { @("Warning") }
            "Error" { @("Error") }
            "Progress" { @("Progress") }
            "Debug" { @("Debug") }
            default { @("Info") }
        }

        Write-Information "$prefix $Message" -Tags $tags
    }
}

Export-ModuleMember -Function Initialize-AuditLogging, Write-AuditLog
