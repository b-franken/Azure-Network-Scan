Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Connect-AzureForAudit {
    <#
    .SYNOPSIS
    Establishes Azure connection for audit operations.

    .DESCRIPTION
    Authenticates to Azure using either service principal credentials (App Registration)
    or interactive browser-based authentication. Validates the connection and logs
    tenant and account details.

    .PARAMETER ClientId
    Azure AD Application (Service Principal) Client ID for non-interactive authentication

    .PARAMETER ClientSecret
    Service Principal secret as SecureString for non-interactive authentication

    .PARAMETER TenantId
    Azure AD Tenant ID for service principal authentication

    .EXAMPLE
    Connect-AzureForAudit
    Authenticates interactively using browser

    .EXAMPLE
    $secret = ConvertTo-SecureString "password" -AsPlainText -Force
    Connect-AzureForAudit -ClientId "app-id" -ClientSecret $secret -TenantId "tenant-id"
    Authenticates using service principal credentials

    .NOTES
    All three parameters (ClientId, ClientSecret, TenantId) must be provided together for service principal auth
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )

    if ($ClientId -and $ClientSecret -and $TenantId) {
        Write-AuditLog "Authenticating using App Registration (ClientId: $ClientId)" -Type Info

        try {
            $credential = [PSCredential]::new($ClientId, $ClientSecret)

            $context = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -ErrorAction Stop

            if ($context) {
                Write-AuditLog "Successfully authenticated with App Registration" -Type Success
                Write-AuditLog "Tenant: $($context.Context.Tenant.Id)" -Type Info
                Write-AuditLog "Account: $($context.Context.Account.Id)" -Type Info
                return $context
            }
            else {
                throw "Connection succeeded but no context was returned"
            }
        }
        catch {
            Write-AuditLog "Failed to authenticate with App Registration: $($_.Exception.Message)" -Type Error
            throw
        }
    }
    else {
        Write-AuditLog "Authenticating interactively" -Type Info

        try {
            $context = Connect-AzAccount -ErrorAction Stop

            if ($context) {
                Write-AuditLog "Successfully authenticated interactively" -Type Success
                Write-AuditLog "Tenant: $($context.Context.Tenant.Id)" -Type Info
                Write-AuditLog "Account: $($context.Context.Account.Id)" -Type Info
                return $context
            }
            else {
                throw "Connection succeeded but no context was returned"
            }
        }
        catch {
            Write-AuditLog "Failed interactive authentication: $($_.Exception.Message)" -Type Error
            throw
        }
    }
}

function Get-AuditSubscriptions {
    <#
    .SYNOPSIS
    Retrieves enabled Azure subscriptions for auditing.

    .DESCRIPTION
    Gets all enabled Azure subscriptions accessible to the current authenticated context.
    Can filter to specific subscription IDs if provided. Validates subscription state
    and excludes disabled subscriptions.

    .PARAMETER SubscriptionIds
    Optional array of specific subscription IDs to audit. If empty, retrieves all enabled subscriptions.

    .EXAMPLE
    Get-AuditSubscriptions
    Returns all enabled subscriptions accessible to the current account

    .EXAMPLE
    Get-AuditSubscriptions -SubscriptionIds "sub-id-1", "sub-id-2"
    Returns only the specified enabled subscriptions

    .OUTPUTS
    System.Object[]
    Returns array of Azure subscription objects

    .NOTES
    Only subscriptions in 'Enabled' state are returned
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [string[]]$SubscriptionIds = @()
    )

    Write-AuditLog "Retrieving subscriptions" -Type Progress

    try {
        if ($SubscriptionIds.Count -eq 0) {
            $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
            Write-AuditLog "Found $($subscriptions.Count) enabled subscriptions" -Type Info
        }
        else {
            $subscriptionsList = [System.Collections.Generic.List[object]]::new()
            foreach ($subId in $SubscriptionIds) {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                if ($sub.State -eq 'Enabled') {
                    $subscriptionsList.Add($sub)
                }
                else {
                    Write-AuditLog "Subscription $subId is in state '$($sub.State)' and will be skipped" -Type Warning
                }
            }
            $subscriptions = @($subscriptionsList.ToArray())
            Write-AuditLog "Validated $($subscriptions.Count) enabled subscriptions from provided list" -Type Info
        }

        if ($subscriptions.Count -eq 0) {
            throw "No enabled subscriptions found to audit"
        }

        return ,$subscriptions
    }
    catch {
        Write-AuditLog "Failed to retrieve subscriptions: $($_.Exception.Message)" -Type Error
        throw
    }
}

Export-ModuleMember -Function Connect-AzureForAudit, Get-AuditSubscriptions
