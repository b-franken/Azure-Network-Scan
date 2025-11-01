Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IPAddressOverlap {
    <#
    .SYNOPSIS
    Tests if two IPv4 CIDR ranges have overlapping address space.

    .DESCRIPTION
    Compares two IPv4 CIDR address ranges to determine if they overlap. IPv6 addresses
    are not supported and will return false. Used to detect address space conflicts
    between Virtual Networks that would prevent peering or cause routing issues.

    .PARAMETER CIDR1
    First CIDR range in format x.x.x.x/mask (e.g., "10.0.0.0/16")

    .PARAMETER CIDR2
    Second CIDR range in format x.x.x.x/mask (e.g., "10.0.1.0/24")

    .EXAMPLE
    Test-IPAddressOverlap -CIDR1 "10.0.0.0/16" -CIDR2 "10.0.1.0/24"
    Returns $true because 10.0.1.0/24 is contained within 10.0.0.0/16

    .EXAMPLE
    Test-IPAddressOverlap -CIDR1 "10.0.0.0/24" -CIDR2 "192.168.0.0/24"
    Returns $false because the ranges do not overlap

    .EXAMPLE
    "10.0.0.0/16" | Test-IPAddressOverlap -CIDR2 "10.0.1.0/24"
    Pipeline example: Returns $true

    .OUTPUTS
    System.Boolean
    Returns $true if the CIDR ranges overlap, $false otherwise

    .NOTES
    IPv6 addresses are automatically detected and return false
    Supports pipeline input for CIDR1 parameter
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$CIDR1,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$CIDR2
    )

    process {
        try {
            $ip1, $mask1 = $CIDR1 -split '/'
            $ip2, $mask2 = $CIDR2 -split '/'

            if ($ip1 -match ':' -or $ip2 -match ':') {
                return $false
            }

            function ConvertTo-IPInteger {
                param([string]$IP)
                try {
                    if ($IP -match ':') {
                        return 0
                    }
                    $bytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
                    [Array]::Reverse($bytes)
                    return [System.BitConverter]::ToUInt32($bytes, 0)
                }
                catch {
                    Write-AuditLog "Failed to parse IP address: $IP" -Type Error
                    return 0
                }
            }

            function Get-NetworkAddress {
                param([uint32]$IP, [int]$MaskBits)
                if ($MaskBits -lt 0 -or $MaskBits -gt 32) {
                    throw "Invalid mask bits: $MaskBits"
                }
                $mask = [uint32]::MaxValue -shl (32 - $MaskBits)
                return ($IP -band $mask)
            }

            $ipInt1 = ConvertTo-IPInteger -IP $ip1
            $ipInt2 = ConvertTo-IPInteger -IP $ip2

            if ($ipInt1 -eq 0 -or $ipInt2 -eq 0) {
                return $false
            }

            $network1 = Get-NetworkAddress -IP $ipInt1 -MaskBits ([int]$mask1)
            $network2 = Get-NetworkAddress -IP $ipInt2 -MaskBits ([int]$mask2)

            $size1 = [uint64]1 -shl (32 - [int]$mask1)
            $size2 = [uint64]1 -shl (32 - [int]$mask2)

            $end1 = $network1 + $size1 - 1
            $end2 = $network2 + $size2 - 1

            $overlap = ($network1 -le $end2) -and ($network2 -le $end1)

            return $overlap
        }
        catch {
            Write-AuditLog "Error checking IP overlap between $CIDR1 and $CIDR2 : $($_.Exception.Message)" -Type Error
            return $false
        }
    }
}

function Get-SubnetUtilization {
    <#
    .SYNOPSIS
    Calculates subnet IP address utilization metrics.

    .DESCRIPTION
    Computes available, used, and total IP addresses for an Azure subnet, accounting
    for Azure's 5 reserved IPs (network, gateway, DNS x2, broadcast). Returns
    utilization percentage to help identify capacity constraints.

    .PARAMETER AddressPrefix
    Subnet CIDR range in format x.x.x.x/mask (e.g., "10.0.1.0/24")

    .PARAMETER UsedIPs
    Number of IPs currently allocated in the subnet (default: 0)

    .EXAMPLE
    Get-SubnetUtilization -AddressPrefix "10.0.1.0/24" -UsedIPs 50
    Returns hashtable with TotalIPs=256, UsedIPs=50, AvailableIPs=201, UtilizationPercent=19.92

    .EXAMPLE
    "10.0.1.0/24" | Get-SubnetUtilization -UsedIPs 50
    Pipeline example: Calculate utilization for piped CIDR

    .OUTPUTS
    System.Collections.Hashtable
    Returns hashtable with keys: TotalIPs, UsedIPs, AvailableIPs, UtilizationPercent, AzureReservedIPs

    .NOTES
    Azure reserves 5 IPs per subnet: .0 (network), .1 (gateway), .2/.3 (DNS), .255 (broadcast)
    Supports pipeline input for AddressPrefix parameter
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')]
        [string]$AddressPrefix,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$UsedIPs = 0
    )

    process {
        try {
            $mask = [int]($AddressPrefix -split '/')[1]
            $totalIPs = [Math]::Pow(2, (32 - $mask))
            $azureReservedIPs = 5
            $availableIPs = $totalIPs - $azureReservedIPs - $UsedIPs
            $utilizationPercent = $totalIPs -gt $azureReservedIPs ? [Math]::Round(($UsedIPs / ($totalIPs - $azureReservedIPs)) * 100, 2) : 0

            return @{
                TotalIPs = $totalIPs
                UsedIPs = $UsedIPs
                AvailableIPs = [Math]::Max(0, $availableIPs)
                UtilizationPercent = $utilizationPercent
                AzureReservedIPs = $azureReservedIPs
            }
        }
        catch {
            Write-AuditLog "Error calculating subnet utilization for $AddressPrefix : $($_.Exception.Message)" -Type Error
            return @{
                TotalIPs = 0
                UsedIPs = 0
                AvailableIPs = 0
                UtilizationPercent = 0
                AzureReservedIPs = 5
            }
        }
    }
}

function New-AuditIssue {
    <#
    .SYNOPSIS
    Creates a new audit issue object with standardized properties.

    .DESCRIPTION
    Generates a PSCustomObject representing an audit finding with timestamp, severity,
    category, description, and optional resource details. Automatically logs the issue
    using Write-AuditLog with appropriate log level based on severity.

    .PARAMETER Severity
    Issue severity level (Critical, High, Medium, Low, Info)

    .PARAMETER Category
    Issue category (e.g., "VNet", "NSG Security", "Private DNS")

    .PARAMETER Title
    Short issue title describing the problem

    .PARAMETER Description
    Detailed description of the issue and its impact

    .PARAMETER ResourceName
    Name of the affected Azure resource (optional)

    .PARAMETER ResourceType
    Type of the affected resource (e.g., "Virtual Network", "NSG") (optional)

    .PARAMETER SubscriptionId
    Azure subscription ID where the resource exists (optional)

    .PARAMETER Remediation
    Recommended remediation steps to fix the issue (optional)

    .EXAMPLE
    $issue = New-AuditIssue -Severity "High" -Category "NSG" -Title "Open RDP port" `
        -Description "NSG allows inbound RDP from Internet" -ResourceName "nsg-prod-web"

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns audit issue object with all properties

    .NOTES
    This function does not modify state, only creates objects
    Severity levels map to log types: Critical=Error, High/Medium=Warning, Low=Info, Info=Debug
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Function only creates objects, does not modify state')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$ResourceName = "",

        [Parameter(Mandatory = $false)]
        [string]$ResourceType = "",

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId = "",

        [Parameter(Mandatory = $false)]
        [string]$Remediation = ""
    )

    $issue = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Severity = $Severity
        Category = $Category
        Title = $Title
        Description = $Description
        ResourceName = $ResourceName
        ResourceType = $ResourceType
        SubscriptionId = $SubscriptionId
        Remediation = $Remediation
    }

    $logType = switch ($Severity) {
        "Critical" { "Error" }
        "High" { "Warning" }
        "Medium" { "Warning" }
        "Low" { "Info" }
        "Info" { "Debug" }
    }

    Write-AuditLog "[$Severity] $Category - $Title : $Description" -Type $logType

    return $issue
}

function Add-AuditIssue {
    <#
    .SYNOPSIS
    Creates and adds an audit issue to the results collection.

    .DESCRIPTION
    Generates an audit issue object with specified severity, category, and details,
    then adds it to the AuditResults hashtable. This is a convenience wrapper around
    New-AuditIssue that automatically adds the issue to the collection.

    .PARAMETER Severity
    Issue severity level (Critical, High, Medium, Low, Info)

    .PARAMETER Category
    Issue category (e.g., "VNet", "NSG Security", "Private DNS")

    .PARAMETER Title
    Short issue title describing the problem

    .PARAMETER Description
    Detailed description of the issue and its impact

    .PARAMETER ResourceName
    Name of the affected Azure resource (optional)

    .PARAMETER ResourceType
    Type of the affected resource (e.g., "Virtual Network", "NSG") (optional)

    .PARAMETER SubscriptionId
    Azure subscription ID where the resource exists (optional)

    .PARAMETER Remediation
    Recommended remediation steps to fix the issue (optional)

    .PARAMETER AuditResults
    Hashtable to store the issue (must have Issues property with severity arrays)

    .EXAMPLE
    Add-AuditIssue -Severity "High" -Category "NSG" -Title "Open RDP port" `
        -Description "NSG allows inbound RDP from Internet" `
        -ResourceName "nsg-prod-web" -AuditResults $results

    .NOTES
    This function modifies the AuditResults hashtable in place
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$ResourceName = "",

        [Parameter(Mandatory = $false)]
        [string]$ResourceType = "",

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId = "",

        [Parameter(Mandatory = $false)]
        [string]$Remediation = "",

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    $issueParams = @{
        Severity = $Severity
        Category = $Category
        Title = $Title
        Description = $Description
        ResourceName = $ResourceName
        ResourceType = $ResourceType
        SubscriptionId = $SubscriptionId
        Remediation = $Remediation
    }

    $issue = New-AuditIssue @issueParams
    $AuditResults.Issues[$Severity] += $issue
}

function Test-VNetProvisioningState {
    <#
    .SYNOPSIS
    Validates Virtual Network provisioning states.

    .DESCRIPTION
    Checks all Virtual Networks for failed or non-Succeeded provisioning states.
    Reports any VNets that are not in a healthy operational state.

    .PARAMETER VNets
    Array of Virtual Network objects to analyze

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-VNetProvisioningState -VNets $vnetArray -AuditResults $results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$VNets,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing VNet provisioning states..." -Type Progress

    foreach ($vnet in $VNets) {
        if ($vnet.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "VNet" -Title "VNet in failed provisioning state" `
                -Description "VNet '$($vnet.name)' is in provisioning state: $($vnet.provisioningState)" `
                -ResourceName $vnet.name -ResourceType "Virtual Network" -SubscriptionId $vnet.subscriptionId `
                -Remediation "Check Azure Portal for deployment errors and re-deploy if necessary" `
                -AuditResults $AuditResults
        }
    }
}

function Test-CIDROverlap {
    <#
    .SYNOPSIS
    Tests if two CIDR ranges have overlapping IP address space.

    .DESCRIPTION
    Performs lightweight CIDR overlap detection by comparing network ranges.
    Returns true if the ranges overlap. IPv6 addresses are detected and return false.
    This function is optimized for use in parallel processing scenarios.

    .PARAMETER CIDR1
    First CIDR range in format x.x.x.x/mask

    .PARAMETER CIDR2
    Second CIDR range in format x.x.x.x/mask

    .EXAMPLE
    Test-CIDROverlap -CIDR1 '10.0.0.0/16' -CIDR2 '10.0.1.0/24'
    Returns $true because the ranges overlap

    .EXAMPLE
    Test-CIDROverlap -CIDR1 '10.0.0.0/24' -CIDR2 '192.168.0.0/24'
    Returns $false because the ranges do not overlap

    .OUTPUTS
    System.Boolean
    Returns $true if CIDRs overlap, $false otherwise

    .NOTES
    This function does not log errors to avoid performance overhead in parallel processing
    IPv6 addresses are not supported and return false
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CIDR1,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CIDR2
    )

    try {
        $ip1, $mask1 = $CIDR1 -split '/'
        $ip2, $mask2 = $CIDR2 -split '/'

        if ($ip1 -match ':' -or $ip2 -match ':') {
            return $false
        }

        $bytes1 = [System.Net.IPAddress]::Parse($ip1).GetAddressBytes()
        [Array]::Reverse($bytes1)
        $ipInt1 = [System.BitConverter]::ToUInt32($bytes1, 0)

        $bytes2 = [System.Net.IPAddress]::Parse($ip2).GetAddressBytes()
        [Array]::Reverse($bytes2)
        $ipInt2 = [System.BitConverter]::ToUInt32($bytes2, 0)

        if ($ipInt1 -eq 0 -or $ipInt2 -eq 0) {
            return $false
        }

        $maskBits1 = [int]$mask1
        $maskBits2 = [int]$mask2

        if ($maskBits1 -lt 0 -or $maskBits1 -gt 32 -or $maskBits2 -lt 0 -or $maskBits2 -gt 32) {
            return $false
        }

        $netmask1 = [uint32]::MaxValue -shl (32 - $maskBits1)
        $netmask2 = [uint32]::MaxValue -shl (32 - $maskBits2)

        $network1 = $ipInt1 -band $netmask1
        $network2 = $ipInt2 -band $netmask2

        $size1 = [uint64]1 -shl (32 - $maskBits1)
        $size2 = [uint64]1 -shl (32 - $maskBits2)

        $end1 = $network1 + $size1 - 1
        $end2 = $network2 + $size2 - 1

        return ($network1 -le $end2) -and ($network2 -le $end1)
    }
    catch {
        return $false
    }
}

function Get-IPv6VNets {
    <#
    .SYNOPSIS
    Identifies Virtual Networks that contain IPv6 address spaces.

    .DESCRIPTION
    Scans all VNet address spaces and returns an array of VNet names that
    have IPv6 CIDR ranges. IPv6 addresses are identified by the presence
    of colon characters in the address space.

    .PARAMETER VNets
    Array of Virtual Network objects to analyze

    .EXAMPLE
    $ipv6VNets = Get-IPv6VNets -VNets $vnetArray

    .OUTPUTS
    System.Array
    Returns array of VNet names that contain IPv6 address spaces

    .NOTES
    IPv6 addresses are not validated for overlaps in this module
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$VNets
    )

    $ipv6VNets = @()
    foreach ($vnet in $VNets) {
        if ($vnet.addressSpace) {
            foreach ($cidr in $vnet.addressSpace) {
                if ($cidr -match ':') {
                    $ipv6VNets += $vnet.name
                    break
                }
            }
        }
    }

    return $ipv6VNets
}

function Invoke-ParallelIPOverlapCheck {
    <#
    .SYNOPSIS
    Performs parallel IP overlap analysis for large VNet environments.

    .DESCRIPTION
    Uses PowerShell parallel processing to check IP address overlaps across
    Virtual Networks. Optimized for environments with large numbers of VNets.
    Returns collection of detected overlaps with detailed information.

    .PARAMETER VNets
    Array of Virtual Network objects to analyze

    .PARAMETER MaxConcurrentQueries
    Maximum number of parallel threads to use

    .EXAMPLE
    $overlaps = Invoke-ParallelIPOverlapCheck -VNets $vnetArray -MaxConcurrentQueries 50

    .OUTPUTS
    System.Collections.Concurrent.ConcurrentBag[object]
    Returns collection of overlap objects with VNet names, subscriptions, and address spaces

    .NOTES
    Uses ForEach-Object -Parallel for concurrent processing
    Displays progress indicators every 10 VNets processed
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Concurrent.ConcurrentBag[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$VNets,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$MaxConcurrentQueries
    )

    Write-AuditLog "Large environment detected ($($VNets.Count) VNets). Using parallel processing..." -Type Info

    $overlaps = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $processedCount = 0
    $startTime = Get-Date
    $vnetCount = $VNets.Count

    $testOverlapScriptBlock = {
        param([string]$CIDR1, [string]$CIDR2)

        try {
            $ip1, $mask1 = $CIDR1 -split '/'
            $ip2, $mask2 = $CIDR2 -split '/'

            if ($ip1 -match ':' -or $ip2 -match ':') {
                return $false
            }

            $bytes1 = [System.Net.IPAddress]::Parse($ip1).GetAddressBytes()
            [Array]::Reverse($bytes1)
            $ipInt1 = [System.BitConverter]::ToUInt32($bytes1, 0)

            $bytes2 = [System.Net.IPAddress]::Parse($ip2).GetAddressBytes()
            [Array]::Reverse($bytes2)
            $ipInt2 = [System.BitConverter]::ToUInt32($bytes2, 0)

            if ($ipInt1 -eq 0 -or $ipInt2 -eq 0) {
                return $false
            }

            $maskBits1 = [int]$mask1
            $maskBits2 = [int]$mask2

            if ($maskBits1 -lt 0 -or $maskBits1 -gt 32 -or $maskBits2 -lt 0 -or $maskBits2 -gt 32) {
                return $false
            }

            $netmask1 = [uint32]::MaxValue -shl (32 - $maskBits1)
            $netmask2 = [uint32]::MaxValue -shl (32 - $maskBits2)

            $network1 = $ipInt1 -band $netmask1
            $network2 = $ipInt2 -band $netmask2

            $size1 = [uint64]1 -shl (32 - $maskBits1)
            $size2 = [uint64]1 -shl (32 - $maskBits2)

            $end1 = $network1 + $size1 - 1
            $end2 = $network2 + $size2 - 1

            return ($network1 -le $end2) -and ($network2 -le $end1)
        }
        catch {
            return $false
        }
    }

    $vnetsToProcess = for ($idx = 0; $idx -lt $VNets.Count; $idx++) {
        [PSCustomObject]@{
            Index = $idx
            VNet = $VNets[$idx]
        }
    }

    $vnetsToProcess | ForEach-Object -Parallel {
        $i = $_.Index
        $vnet1 = $_.VNet
        $allVNets = $using:VNets
        $vnetCount = $using:vnetCount
        $overlapsCollection = $using:overlaps
        $testOverlap = $using:testOverlapScriptBlock
        $processed = $using:processedCount
        $startTime = $using:startTime

        if (!$vnet1.addressSpace -or $vnet1.addressSpace.Count -eq 0) {
            return
        }

        foreach ($addr1 in $vnet1.addressSpace) {
            for ($j = $i + 1; $j -lt $vnetCount; $j++) {
                $vnet2 = $allVNets[$j]

                if (!$vnet2.addressSpace -or $vnet2.addressSpace.Count -eq 0) {
                    continue
                }

                foreach ($addr2 in $vnet2.addressSpace) {
                    if (& $testOverlap -CIDR1 $addr1 -CIDR2 $addr2) {
                        $overlapsCollection.Add([PSCustomObject]@{
                            VNet1 = $vnet1.name
                            VNet1Subscription = $vnet1.subscriptionId
                            AddressSpace1 = $addr1
                            VNet2 = $vnet2.name
                            VNet2Subscription = $vnet2.subscriptionId
                            AddressSpace2 = $addr2
                        })
                    }
                }
            }
        }

        $completed = [System.Threading.Interlocked]::Increment([ref]$processed)
        if ($completed % 10 -eq 0) {
            $percentComplete = [Math]::Round(($completed / $vnetCount) * 100, 1)
            $elapsed = (Get-Date) - $startTime
            $estimatedTotal = if ($completed -gt 0) {
                $elapsed.TotalSeconds / $completed * $vnetCount
            } else { 0 }
            $remaining = [Math]::Max(0, [int]($estimatedTotal - $elapsed.TotalSeconds))

            Write-Progress -Activity 'Analyzing IP Address Overlaps' `
                          -Status "$completed / $vnetCount VNets analyzed" `
                          -PercentComplete $percentComplete `
                          -SecondsRemaining $remaining

            Write-Information "Progress: $completed / $vnetCount VNets analyzed ($percentComplete%) - Est. $remaining seconds remaining" -InformationAction Continue -Tags @('Progress')
        }
    } -ThrottleLimit $MaxConcurrentQueries

    Write-Progress -Activity 'Analyzing IP Address Overlaps' -Completed
    Write-AuditLog "Parallel processing complete: $processedCount VNets analyzed" -Type Info

    return $overlaps
}

function Invoke-SequentialIPOverlapCheck {
    <#
    .SYNOPSIS
    Performs sequential IP overlap analysis for smaller VNet environments.

    .DESCRIPTION
    Checks IP address overlaps using sequential processing. More efficient
    for smaller environments where parallel processing overhead is not justified.
    Displays progress indicators and logs progress periodically.

    .PARAMETER VNets
    Array of Virtual Network objects to analyze

    .EXAMPLE
    $overlaps = Invoke-SequentialIPOverlapCheck -VNets $vnetArray

    .OUTPUTS
    System.Collections.ArrayList
    Returns collection of overlap objects with VNet names, subscriptions, and address spaces

    .NOTES
    Uses Test-IPAddressOverlap function for overlap detection
    Progress logged every 10 VNets processed
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$VNets
    )

    Write-AuditLog "Standard sequential processing for $($VNets.Count) VNets..." -Type Info

    $overlaps = [System.Collections.ArrayList]::new()
    $vnetCount = $VNets.Count

    for ($i = 0; $i -lt $vnetCount; $i++) {
        $vnet1 = $VNets[$i]

        if ($i % 10 -eq 0) {
            $percentComplete = [Math]::Round(($i / $vnetCount) * 100, 2)

            Write-Progress -Activity 'Analyzing IP Address Overlaps' `
                          -Status "$i / $vnetCount VNets analyzed" `
                          -PercentComplete $percentComplete

            Write-AuditLog "Progress: $percentComplete% ($i / $vnetCount VNets checked)" -Type Debug
        }

        if (!$vnet1.addressSpace -or $vnet1.addressSpace.Count -eq 0) {
            continue
        }

        foreach ($addr1 in $vnet1.addressSpace) {
            for ($j = $i + 1; $j -lt $vnetCount; $j++) {
                $vnet2 = $VNets[$j]

                if (!$vnet2.addressSpace -or $vnet2.addressSpace.Count -eq 0) {
                    continue
                }

                foreach ($addr2 in $vnet2.addressSpace) {
                    if (Test-IPAddressOverlap -CIDR1 $addr1 -CIDR2 $addr2) {
                        $null = $overlaps.Add([PSCustomObject]@{
                            VNet1 = $vnet1.name
                            VNet1Subscription = $vnet1.subscriptionId
                            AddressSpace1 = $addr1
                            VNet2 = $vnet2.name
                            VNet2Subscription = $vnet2.subscriptionId
                            AddressSpace2 = $addr2
                        })
                    }
                }
            }
        }
    }

    Write-Progress -Activity 'Analyzing IP Address Overlaps' -Completed

    return $overlaps
}

function Test-IPAddressOverlaps {
    <#
    .SYNOPSIS
    Analyzes all Virtual Networks for IP address space overlaps.

    .DESCRIPTION
    Performs pairwise comparison of all VNet address spaces to detect overlapping
    CIDR ranges. Uses parallel processing for large environments. IPv6 ranges are
    detected but not validated for overlaps.

    .PARAMETER VNets
    Array of Virtual Network objects to analyze

    .PARAMETER MaxConcurrentQueries
    Maximum number of parallel processing threads (triggers parallel mode if VNet count exceeds this)

    .PARAMETER AuditResults
    Hashtable to store identified overlaps as Critical issues

    .EXAMPLE
    Test-IPAddressOverlaps -VNets $vnetArray -MaxConcurrentQueries 50 -AuditResults $results

    .NOTES
    For environments with more VNets than MaxConcurrentQueries, uses ForEach-Object -Parallel
    IPv6 address spaces are logged but not validated
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$VNets,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$MaxConcurrentQueries,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$AuditResults
    )

    Write-AuditLog 'Analyzing IP address overlaps (this may take several minutes for large environments)...' -Type Progress

    Write-Progress -Activity 'IP Address Overlap Analysis' -Status 'Identifying IPv6 networks...' -PercentComplete 0

    $ipv6VNets = @(Get-IPv6VNets -VNets $VNets)

    if ($ipv6VNets.Count -gt 0) {
        $ipv6List = ($ipv6VNets | Select-Object -First 5) -join ', '
        if ($ipv6VNets.Count -gt 5) {
            $ipv6List += " and $($ipv6VNets.Count - 5) more"
        }
        Add-AuditIssue -Severity 'Info' -Category 'IP Addressing' -Title 'IPv6 address spaces detected' `
            -Description "IPv6 address spaces are not validated for overlaps. IPv6 VNets: $ipv6List" `
            -ResourceName 'Multiple VNets' -ResourceType 'Virtual Network' -SubscriptionId 'N/A' `
            -Remediation 'Manually verify IPv6 address space overlaps if using IPv6' `
            -AuditResults $AuditResults
        Write-AuditLog "Detected $($ipv6VNets.Count) VNets with IPv6 addresses - overlap validation skipped for IPv6" -Type Info
    }

    $vnetCount = $VNets.Count

    Write-Progress -Activity 'IP Address Overlap Analysis' -Status "Analyzing $vnetCount VNets..." -PercentComplete 10

    $overlaps = if ($vnetCount -gt $MaxConcurrentQueries) {
        Invoke-ParallelIPOverlapCheck -VNets $VNets -MaxConcurrentQueries $MaxConcurrentQueries
    } else {
        Invoke-SequentialIPOverlapCheck -VNets $VNets
    }

    $overlapsDetected = 0
    foreach ($overlap in $overlaps) {
        $overlapsDetected++
        Add-AuditIssue -Severity 'Critical' -Category 'IP Overlap' -Title 'IP address space overlap detected' `
            -Description "VNet '$($overlap.VNet1)' ($($overlap.AddressSpace1)) overlaps with VNet '$($overlap.VNet2)' ($($overlap.AddressSpace2)). This will cause routing issues and prevent VNet peering." `
            -ResourceName "$($overlap.VNet1) <-> $($overlap.VNet2)" -ResourceType 'Virtual Network' `
            -SubscriptionId "$($overlap.VNet1Subscription) | $($overlap.VNet2Subscription)" `
            -Remediation 'Redesign IP address allocation or migrate one VNet to a different address space. Ensure proper IPAM (IP Address Management) strategy.' `
            -AuditResults $AuditResults
    }

    Write-Progress -Activity 'IP Address Overlap Analysis' -Completed

    Write-AuditLog "IP overlap analysis complete. Found $overlapsDetected overlaps." -Type $(if ($overlapsDetected -gt 0) { 'Warning' } else { 'Success' })
}

function Test-VNetPeerings {
    <#
    .SYNOPSIS
    Validates Virtual Network peering configurations and states.

    .DESCRIPTION
    Analyzes VNet peerings for connectivity issues, invalid gateway transit configurations,
    and missing forwarded traffic settings required for hub-spoke topologies.

    .PARAMETER VNets
    Array of Virtual Network objects with peering information

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-VNetPeerings -VNets $vnetArray -AuditResults $results

    .NOTES
    Detects peerings not in Connected state, conflicting gateway transit settings,
    and missing allowForwardedTraffic for hub-spoke scenarios
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$VNets,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing VNet Peering configurations..." -Type Progress

    foreach ($vnet in $VNets) {
        if (!$vnet.peerings -or $vnet.peerings.Count -eq 0) {
            continue
        }

        foreach ($peering in $vnet.peerings) {
            $peeringState = $peering.properties.peeringState
            $peeringName = $peering.name
            $remoteVNetId = $peering.properties.remoteVirtualNetwork.id
            $remoteVNetName = $remoteVNetId ? ($remoteVNetId -split '/')[-1] : 'Unknown'

            if ($peeringState -ne "Connected") {
                Add-AuditIssue -Severity "High" -Category "VNet Peering" -Title "VNet peering not in Connected state" `
                    -Description "Peering '$peeringName' from VNet '$($vnet.name)' to '$remoteVNetName' is in state: $peeringState" `
                    -ResourceName $vnet.name -ResourceType "Virtual Network Peering" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Verify remote VNet exists and peering is configured bidirectionally. Check for conflicting address spaces." `
                    -AuditResults $AuditResults
            }

            if ($peering.properties.allowGatewayTransit -and $peering.properties.useRemoteGateways) {
                Add-AuditIssue -Severity "High" -Category "VNet Peering" -Title "Invalid gateway transit configuration" `
                    -Description "Peering '$peeringName' has both allowGatewayTransit and useRemoteGateways enabled, which is not allowed" `
                    -ResourceName $vnet.name -ResourceType "Virtual Network Peering" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Disable either allowGatewayTransit or useRemoteGateways. Only one can be enabled per peering direction." `
                    -AuditResults $AuditResults
            }

            if ($peeringState -eq "Connected" -and !$peering.properties.allowForwardedTraffic) {
                Add-AuditIssue -Severity "Low" -Category "VNet Peering" -Title "Forwarded traffic not allowed" `
                    -Description "Peering '$peeringName' does not allow forwarded traffic, which may limit hub-spoke scenarios" `
                    -ResourceName $vnet.name -ResourceType "Virtual Network Peering" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Consider enabling allowForwardedTraffic if using hub-spoke topology with Network Virtual Appliances." `
                    -AuditResults $AuditResults
            }
        }
    }
}

function Test-PrivateDNSZones {
    <#
    .SYNOPSIS
    Analyzes Private DNS Zones for configuration issues.

    .DESCRIPTION
    Validates Private DNS Zone provisioning states, detects duplicate zones across
    subscriptions (split-brain DNS), identifies orphaned zones with no VNet links,
    and checks for missing auto-registration.

    .PARAMETER PrivateDNSZones
    Array of Private DNS Zone objects to analyze (can be empty)

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-PrivateDNSZones -PrivateDNSZones $dnsArray -AuditResults $results

    .NOTES
    Duplicate zones cause split-brain DNS and resolution failures
    Zones without VNet links are non-functional
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$PrivateDNSZones,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing Private DNS Zones..." -Type Progress

    if ($PrivateDNSZones.Count -eq 0) {
        Write-AuditLog "No Private DNS Zones found - skipping analysis" -Type Info
        return
    }

    $dnsZoneGroups = $PrivateDNSZones | Group-Object -Property name

    foreach ($group in $dnsZoneGroups) {
        if ($group.Count -gt 1) {
            $subscriptionList = ($group.Group.subscriptionId | Select-Object -Unique) -join ', '
            $locationList = ($group.Group | ForEach-Object { "$($_.subscriptionId)/$($_.resourceGroup)" }) -join ' | '

            Add-AuditIssue -Severity "High" -Category "Private DNS" -Title "Duplicate Private DNS Zone" `
                -Description "DNS Zone '$($group.Name)' exists in $($group.Count) locations: $locationList. This causes split-brain DNS and resolution issues." `
                -ResourceName $group.Name -ResourceType "Private DNS Zone" -SubscriptionId $subscriptionList `
                -Remediation "Consolidate to single Private DNS Zone in hub subscription. Delete duplicates and relink VNets to central zone." `
                -AuditResults $AuditResults
        }
    }

    foreach ($zone in $PrivateDNSZones) {
        if ($zone.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "Private DNS" -Title "DNS Zone in failed state" `
                -Description "Private DNS Zone '$($zone.name)' is in provisioning state: $($zone.provisioningState)" `
                -ResourceName $zone.name -ResourceType "Private DNS Zone" -SubscriptionId $zone.subscriptionId `
                -Remediation "Check Azure Portal for errors and re-create zone if necessary" `
                -AuditResults $AuditResults
        }

        if ($zone.numberOfVirtualNetworkLinks -eq 0) {
            Add-AuditIssue -Severity "Medium" -Category "Private DNS" -Title "Orphaned Private DNS Zone" `
                -Description "Private DNS Zone '$($zone.name)' has no VNet links - not being used for name resolution" `
                -ResourceName $zone.name -ResourceType "Private DNS Zone" -SubscriptionId $zone.subscriptionId `
                -Remediation "Link to VNets that need resolution or delete if no longer needed" `
                -AuditResults $AuditResults
        }

        if ($zone.numberOfVirtualNetworkLinks -gt 0 -and $zone.numberOfVirtualNetworkLinksWithRegistration -eq 0 -and $zone.name -notmatch "privatelink") {
            Add-AuditIssue -Severity "Info" -Category "Private DNS" -Title "No auto-registration enabled" `
                -Description "Private DNS Zone '$($zone.name)' has VNet links but none have auto-registration enabled" `
                -ResourceName $zone.name -ResourceType "Private DNS Zone" -SubscriptionId $zone.subscriptionId `
                -Remediation "Enable auto-registration on at least one VNet link if dynamic DNS registration is needed" `
                -AuditResults $AuditResults
        }
    }
}

function Test-VNetLinks {
    <#
    .SYNOPSIS
    Validates VNet links to Private DNS Zones.

    .DESCRIPTION
    Checks VNet links for failed provisioning or incomplete states. Identifies VNets
    not linked to any Private DNS zones, which prevents private endpoint name resolution.

    .PARAMETER VNetLinks
    Array of VNet link objects to analyze (can be empty)

    .PARAMETER VNets
    Array of Virtual Network objects to cross-reference

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-VNetLinks -VNetLinks $linkArray -VNets $vnetArray -AuditResults $results

    .NOTES
    VNets without DNS links cannot resolve private endpoint FQDNs
    Links must be in Completed state for DNS resolution to work
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$VNetLinks,

        [Parameter(Mandatory = $true)]
        [array]$VNets,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing VNet Links..." -Type Progress

    if ($VNetLinks.Count -eq 0) {
        Write-AuditLog "No VNet Links found - skipping analysis" -Type Info
        return
    }

    foreach ($link in $VNetLinks) {
        if ($link.linkState -ne "Completed") {
            Add-AuditIssue -Severity "High" -Category "VNet Link" -Title "VNet link not in Completed state" `
                -Description "VNet link '$($link.name)' for DNS zone '$($link.zoneName)' is in state: $($link.linkState)" `
                -ResourceName $link.name -ResourceType "VNet Link" -SubscriptionId $link.subscriptionId `
                -Remediation "Check VNet and DNS zone provisioning state. Delete and re-create link if stuck." `
                -AuditResults $AuditResults
        }

        if ($link.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "VNet Link" -Title "VNet link provisioning failed" `
                -Description "VNet link '$($link.name)' for DNS zone '$($link.zoneName)' is in provisioning state: $($link.provisioningState)" `
                -ResourceName $link.name -ResourceType "VNet Link" -SubscriptionId $link.subscriptionId `
                -Remediation "Check for RBAC permissions and resource locks. Re-create link if necessary." `
                -AuditResults $AuditResults
        }
    }

    $vnetsWithoutDNSLinks = @()
    foreach ($vnet in $VNets) {
        $hasLink = $VNetLinks | Where-Object { $_.vnetId -eq $vnet.id }

        if (!$hasLink -and $vnet.name -notmatch "Gateway" -and $vnet.provisioningState -eq "Succeeded") {
            $vnetsWithoutDNSLinks += $vnet

            Add-AuditIssue -Severity "Medium" -Category "VNet Link" -Title "VNet not linked to any Private DNS Zone" `
                -Description "VNet '$($vnet.name)' has no Private DNS zone links. VMs will use Azure default DNS (168.63.129.16) without private endpoint resolution." `
                -ResourceName $vnet.name -ResourceType "Virtual Network" -SubscriptionId $vnet.subscriptionId `
                -Remediation "Link VNet to centralized Private DNS zones for proper private endpoint name resolution" `
                -AuditResults $AuditResults
        }
    }
}

function Test-PrivateEndpoints {
    <#
    .SYNOPSIS
    Validates Private Endpoint configurations and DNS integration.

    .DESCRIPTION
    Analyzes Private Endpoints for provisioning failures, unapproved connections,
    missing DNS configurations, and validates that VNets have required Private DNS
    zone links for proper name resolution.

    .PARAMETER PrivateEndpoints
    Array of Private Endpoint objects to analyze (can be empty)

    .PARAMETER VNetLinks
    Array of VNet link objects for DNS zone validation (can be empty)

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-PrivateEndpoints -PrivateEndpoints $peArray -VNetLinks $linkArray -AuditResults $results

    .NOTES
    Validates service-specific DNS zones (blob, file, SQL, Key Vault, etc.)
    Private Endpoints require approved connections and proper DNS integration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$PrivateEndpoints,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$VNetLinks,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing Private Endpoints..." -Type Progress

    if ($PrivateEndpoints.Count -eq 0) {
        Write-AuditLog "No Private Endpoints found - skipping analysis" -Type Info
        return
    }

    foreach ($pe in $PrivateEndpoints) {
        if ($pe.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "Private Endpoint" -Title "Private Endpoint provisioning failed" `
                -Description "Private Endpoint '$($pe.name)' is in provisioning state: $($pe.provisioningState)" `
                -ResourceName $pe.name -ResourceType "Private Endpoint" -SubscriptionId $pe.subscriptionId `
                -Remediation "Check target resource and subnet configuration. Verify no IP conflicts exist." `
                -AuditResults $AuditResults
        }

        if ($pe.connectionState -and $pe.connectionState -ne "Approved") {
            Add-AuditIssue -Severity "High" -Category "Private Endpoint" -Title "Private Endpoint connection not approved" `
                -Description "Private Endpoint '$($pe.name)' connection is in state: $($pe.connectionState)" `
                -ResourceName $pe.name -ResourceType "Private Endpoint" -SubscriptionId $pe.subscriptionId `
                -Remediation "Approve the Private Endpoint connection on the target resource" `
                -AuditResults $AuditResults
        }

        if (!$pe.customDnsConfigs -or $pe.customDnsConfigs.Count -eq 0) {
            Add-AuditIssue -Severity "Medium" -Category "Private Endpoint" -Title "Private Endpoint missing DNS configuration" `
                -Description "Private Endpoint '$($pe.name)' has no custom DNS configuration. May not be properly integrated with Private DNS." `
                -ResourceName $pe.name -ResourceType "Private Endpoint" -SubscriptionId $pe.subscriptionId `
                -Remediation "Verify Private DNS Zone integration is configured. Check that DNS zone exists and is linked." `
                -AuditResults $AuditResults
        }

        if ($pe.subnetId) {
            $vnetId = ($pe.subnetId -split '/subnets/')[0]
            $linkedZones = $VNetLinks | Where-Object { $_.vnetId -eq $vnetId }

            if ($linkedZones.Count -eq 0) {
                Add-AuditIssue -Severity "High" -Category "Private Endpoint" -Title "Private Endpoint VNet not linked to DNS zones" `
                    -Description "Private Endpoint '$($pe.name)' is in a VNet that has no Private DNS zone links. DNS resolution will fail." `
                    -ResourceName $pe.name -ResourceType "Private Endpoint" -SubscriptionId $pe.subscriptionId `
                    -Remediation "Link the VNet to appropriate Private DNS zones (e.g., privatelink.blob.core.windows.net)" `
                    -AuditResults $AuditResults
            }

            if ($pe.groupIds -and $pe.groupIds.Count -gt 0) {
                $groupId = $pe.groupIds[0]
                $expectedZoneSuffix = switch ($groupId) {
                    "blob" { "privatelink.blob.core.windows.net" }
                    "file" { "privatelink.file.core.windows.net" }
                    "queue" { "privatelink.queue.core.windows.net" }
                    "table" { "privatelink.table.core.windows.net" }
                    "web" { "privatelink.web.core.windows.net" }
                    "dfs" { "privatelink.dfs.core.windows.net" }
                    "sqlServer" { "privatelink.database.windows.net" }
                    "Sql" { "privatelink.documents.azure.com" }
                    "MongoDB" { "privatelink.mongo.cosmos.azure.com" }
                    "postgresqlServer" { "privatelink.postgres.database.azure.com" }
                    "mysqlServer" { "privatelink.mysql.database.azure.com" }
                    "mariadbServer" { "privatelink.mariadb.database.azure.com" }
                    "registry" { "privatelink.azurecr.io" }
                    "sites" { "privatelink.azurewebsites.net" }
                    "staticSites" { "privatelink.azurestaticapps.net" }
                    "vault" { "privatelink.vaultcore.azure.net" }
                    "namespace" { "privatelink.servicebus.windows.net" }
                    default { $null }
                }

                if ($expectedZoneSuffix) {
                    $hasCorrectZone = $false
                    foreach ($link in $linkedZones) {
                        if ($link.zoneName -eq $expectedZoneSuffix) {
                            $hasCorrectZone = $true
                            break
                        }
                    }

                    if (!$hasCorrectZone) {
                        Add-AuditIssue -Severity "High" -Category "Private Endpoint" -Title "Missing required Private DNS Zone" `
                            -Description "Private Endpoint '$($pe.name)' requires DNS zone '$expectedZoneSuffix' but VNet is not linked to it" `
                            -ResourceName $pe.name -ResourceType "Private Endpoint" -SubscriptionId $pe.subscriptionId `
                            -Remediation "Create Private DNS Zone '$expectedZoneSuffix' and link to VNet, or link to existing zone in hub" `
                            -AuditResults $AuditResults
                    }
                }
            }
        }
    }
}

function Test-SubnetUtilization {
    <#
    .SYNOPSIS
    Analyzes subnet IP address utilization and capacity.

    .DESCRIPTION
    Calculates IP utilization for all subnets across Virtual Networks. Reports
    subnets approaching capacity (80%+) and identifies empty unused subnets.

    .PARAMETER VNets
    Array of Virtual Network objects with subnet information

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-SubnetUtilization -VNets $vnetArray -AuditResults $results

    .NOTES
    High severity for 90%+ utilization, Medium for 80%+
    Empty subnets are reported as Info level findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$VNets,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing subnet utilization..." -Type Progress

    foreach ($vnet in $VNets) {
        if (!$vnet.subnets -or $vnet.subnets.Count -eq 0) {
            Add-AuditIssue -Severity "Low" -Category "VNet" -Title "VNet has no subnets" `
                -Description "VNet '$($vnet.name)' has no subnets defined" `
                -ResourceName $vnet.name -ResourceType "Virtual Network" -SubscriptionId $vnet.subscriptionId `
                -Remediation "Create subnets or delete VNet if not needed" `
                -AuditResults $AuditResults
            continue
        }

        foreach ($subnet in $vnet.subnets) {
            try {
                $subnetName = $subnet.name
                $addressPrefix = $null

                if ($subnet.PSObject.Properties['addressPrefix']) {
                    $addressPrefix = $subnet.addressPrefix
                } elseif ($subnet.PSObject.Properties['properties'] -and $subnet.properties.PSObject.Properties['addressPrefix']) {
                    $addressPrefix = $subnet.properties.addressPrefix
                }

                if (!$addressPrefix) {
                    continue
                }

                $ipConfigCount = 0
                if ($subnet.PSObject.Properties['ipConfigurations']) {
                    $ipConfigCount = @($subnet.ipConfigurations).Count
                } elseif ($subnet.PSObject.Properties['properties'] -and $subnet.properties.PSObject.Properties['ipConfigurations']) {
                    $ipConfigCount = @($subnet.properties.ipConfigurations).Count
                }

                $utilization = Get-SubnetUtilization -AddressPrefix $addressPrefix -UsedIPs $ipConfigCount
            } catch {
                Write-AuditLog "Error processing subnet $($subnet.name): $_" -Type Warning
                continue
            }

            if ($utilization.UtilizationPercent -ge 90) {
                Add-AuditIssue -Severity "High" -Category "Subnet" -Title "Subnet near capacity" `
                    -Description "Subnet '$subnetName' in VNet '$($vnet.name)' is $($utilization.UtilizationPercent)% utilized ($($utilization.UsedIPs)/$($utilization.TotalIPs - $utilization.AzureReservedIPs) IPs used)" `
                    -ResourceName "$($vnet.name)/$subnetName" -ResourceType "Subnet" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Expand subnet address space or create additional subnet. Plan for growth." `
                    -AuditResults $AuditResults
            }
            elseif ($utilization.UtilizationPercent -ge 80) {
                Add-AuditIssue -Severity "Medium" -Category "Subnet" -Title "Subnet utilization high" `
                    -Description "Subnet '$subnetName' in VNet '$($vnet.name)' is $($utilization.UtilizationPercent)% utilized ($($utilization.UsedIPs)/$($utilization.TotalIPs - $utilization.AzureReservedIPs) IPs used)" `
                    -ResourceName "$($vnet.name)/$subnetName" -ResourceType "Subnet" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Monitor growth and plan for expansion" `
                    -AuditResults $AuditResults
            }

            if ($ipConfigCount -eq 0 -and $subnetName -notmatch "Gateway|AzureFirewall|AzureBastionSubnet") {
                Add-AuditIssue -Severity "Info" -Category "Subnet" -Title "Empty subnet" `
                    -Description "Subnet '$subnetName' in VNet '$($vnet.name)' has no resources deployed" `
                    -ResourceName "$($vnet.name)/$subnetName" -ResourceType "Subnet" -SubscriptionId $vnet.subscriptionId `
                    -Remediation "Deploy resources or delete subnet to reduce complexity" `
                    -AuditResults $AuditResults
            }
        }
    }
}

function Test-NetworkSecurityGroups {
    <#
    .SYNOPSIS
    Performs security analysis on Network Security Groups.

    .DESCRIPTION
    Analyzes NSG rules for security risks including wildcard configurations,
    overly permissive inbound rules from Internet, high-priority rules, and
    identifies orphaned NSGs not attached to any resources.

    .PARAMETER NSGs
    Array of Network Security Group objects to analyze (can be empty)

    .PARAMETER AuditResults
    Hashtable to store identified security issues

    .EXAMPLE
    Test-NetworkSecurityGroups -NSGs $nsgArray -AuditResults $results

    .NOTES
    Critical issues: Inbound Allow rules from Internet with wildcards
    High issues: Other Allow rules with wildcards
    Validates protocol, source, destination, and port configurations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$NSGs,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing Network Security Groups..." -Type Progress

    if ($NSGs.Count -eq 0) {
        Write-AuditLog "No Network Security Groups found - skipping analysis" -Type Info
        return
    }

    $orphanedNSGs = 0
    $wildcardRuleCount = 0
    $criticalWildcardRules = 0

    foreach ($nsg in $NSGs) {
        $hasAttachment = ($nsg.subnets -and $nsg.subnets.Count -gt 0) -or ($nsg.networkInterfaces -and $nsg.networkInterfaces.Count -gt 0)

        if (!$hasAttachment) {
            $orphanedNSGs++
            Add-AuditIssue -Severity "Low" -Category "NSG" -Title "Orphaned Network Security Group" `
                -Description "NSG '$($nsg.name)' is not attached to any subnet or network interface" `
                -ResourceName $nsg.name -ResourceType "Network Security Group" -SubscriptionId $nsg.subscriptionId `
                -Remediation "Delete NSG if not needed or attach to subnet/NIC" `
                -AuditResults $AuditResults
        }

        if ($nsg.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "NSG" -Title "NSG provisioning failed" `
                -Description "NSG '$($nsg.name)' is in provisioning state: $($nsg.provisioningState)" `
                -ResourceName $nsg.name -ResourceType "Network Security Group" -SubscriptionId $nsg.subscriptionId `
                -Remediation "Check for policy violations or quota limits. Re-create NSG if necessary." `
                -AuditResults $AuditResults
        }

        if ($nsg.securityRules -and $nsg.securityRules.Count -gt 0) {
            foreach ($rule in $nsg.securityRules) {
                $ruleName = $rule.name
                $ruleProps = $rule.properties

                if (!$ruleProps) {
                    continue
                }

                $protocol = $ruleProps.protocol
                $sourceAddressPrefix = $ruleProps.sourceAddressPrefix
                $sourceAddressPrefixes = $ruleProps.sourceAddressPrefixes
                $destinationAddressPrefix = $ruleProps.destinationAddressPrefix
                $destinationAddressPrefixes = $ruleProps.destinationAddressPrefixes
                $destinationPortRange = $ruleProps.destinationPortRange
                $destinationPortRanges = $ruleProps.destinationPortRanges
                $access = $ruleProps.access
                $direction = $ruleProps.direction
                $priority = $ruleProps.priority

                $hasWildcard = $false
                $wildcardDetails = @()
                $severity = "Medium"

                if ($protocol -eq "*") {
                    $hasWildcard = $true
                    $wildcardDetails += "protocol: ANY"
                }

                $hasInternetSource = $false
                $allSources = @($sourceAddressPrefix) + $sourceAddressPrefixes | Where-Object { $_ }
                foreach ($source in $allSources) {
                    if ($source -in @("*", "Internet", "0.0.0.0/0", "::/0")) {
                        $hasWildcard = $true
                        $hasInternetSource = $true
                        $wildcardDetails += "source: $source"
                    }
                }

                $allDestinations = @($destinationAddressPrefix) + $destinationAddressPrefixes | Where-Object { $_ }
                foreach ($dest in $allDestinations) {
                    if ($dest -in @("*", "Internet", "0.0.0.0/0", "::/0")) {
                        $hasWildcard = $true
                        $wildcardDetails += "destination: $dest"
                    }
                }

                $allDestPorts = @($destinationPortRange) + $destinationPortRanges | Where-Object { $_ }
                foreach ($port in $allDestPorts) {
                    if ($port -eq "*") {
                        $hasWildcard = $true
                        $wildcardDetails += "destination port: ANY"
                    }
                }

                if ($hasWildcard) {
                    $wildcardRuleCount++

                    $wildcardString = $wildcardDetails -join ", "
                    $attachmentType = if ($nsg.subnets -and $nsg.subnets.Count -gt 0) {
                        "subnet-level (affects all resources in subnet)"
                    } elseif ($nsg.networkInterfaces -and $nsg.networkInterfaces.Count -gt 0) {
                        "NIC-level"
                    } else {
                        "unattached"
                    }

                    if ($access -eq "Allow" -and $direction -eq "Inbound" -and $hasInternetSource) {
                        $severity = "Critical"
                        $criticalWildcardRules++

                        Add-AuditIssue -Severity $severity -Category "NSG Security" -Title "Critical wildcard NSG rule allows unrestricted inbound access" `
                            -Description "NSG '$($nsg.name)' rule '$ruleName' (priority $priority) uses wildcards ($wildcardString) and allows inbound traffic from Internet/Any. This is a $attachmentType NSG exposing resources to the public internet." `
                            -ResourceName "$($nsg.name)/$ruleName" -ResourceType "Network Security Group Rule" -SubscriptionId $nsg.subscriptionId `
                            -Remediation "Apply principle of least privilege: specify exact source IPs/CIDRs, protocols, and ports. Remove wildcard values and restrict access to known trusted sources only. Consider using Application Security Groups for granular control." `
                            -AuditResults $AuditResults
                    }
                    elseif ($access -eq "Allow") {
                        if ($direction -eq "Inbound") {
                            $severity = "High"
                        } else {
                            $severity = "Medium"
                        }

                        Add-AuditIssue -Severity $severity -Category "NSG Security" -Title "NSG rule uses wildcard configuration" `
                            -Description "NSG '$($nsg.name)' rule '$ruleName' (priority $priority, $direction $access) uses wildcards: $wildcardString. This is a $attachmentType NSG violating least privilege principle." `
                            -ResourceName "$($nsg.name)/$ruleName" -ResourceType "Network Security Group Rule" -SubscriptionId $nsg.subscriptionId `
                            -Remediation "Specify explicit values instead of wildcards. Define specific protocols, source/destination addresses, and port ranges based on application requirements." `
                            -AuditResults $AuditResults
                    }
                    else {
                        Add-AuditIssue -Severity "Info" -Category "NSG Security" -Title "NSG deny rule uses wildcards" `
                            -Description "NSG '$($nsg.name)' rule '$ruleName' (priority $priority, $direction Deny) uses wildcards: $wildcardString. While deny rules with wildcards are less risky, explicit rules are recommended for clarity." `
                            -ResourceName "$($nsg.name)/$ruleName" -ResourceType "Network Security Group Rule" -SubscriptionId $nsg.subscriptionId `
                            -Remediation "Consider using explicit values for better rule documentation and maintenance." `
                            -AuditResults $AuditResults
                    }
                }

                if ($access -eq "Allow" -and $direction -eq "Inbound" -and $priority -lt 100) {
                    $highPrioritySource = $sourceAddressPrefix
                    if (!$highPrioritySource -and $sourceAddressPrefixes -and $sourceAddressPrefixes.Count -gt 0) {
                        $highPrioritySource = $sourceAddressPrefixes[0]
                    }

                    Add-AuditIssue -Severity "Medium" -Category "NSG Security" -Title "High-priority allow rule in NSG" `
                        -Description "NSG '$($nsg.name)' rule '$ruleName' has very high priority ($priority) and allows inbound $protocol traffic from $highPrioritySource. High priority rules override other security rules." `
                        -ResourceName "$($nsg.name)/$ruleName" -ResourceType "Network Security Group Rule" -SubscriptionId $nsg.subscriptionId `
                        -Remediation "Review if this high priority is necessary. Use priority ranges: 100-999 for custom rules, reserving <100 for critical exceptions only." `
                        -AuditResults $AuditResults
                }
            }
        }
    }

    if ($wildcardRuleCount -gt 0) {
        Write-AuditLog "Found $wildcardRuleCount NSG rules with wildcard configurations ($criticalWildcardRules critical)" -Type Warning
    }
}

function Test-RouteTables {
    <#
    .SYNOPSIS
    Validates Route Table configurations and attachments.

    .DESCRIPTION
    Analyzes Route Tables for provisioning failures, identifies orphaned tables
    not attached to subnets, and detects disabled BGP route propagation that
    would prevent ExpressRoute/VPN routes from propagating.

    .PARAMETER RouteTables
    Array of Route Table objects to analyze (can be empty)

    .PARAMETER AuditResults
    Hashtable to store identified issues

    .EXAMPLE
    Test-RouteTables -RouteTables $rtArray -AuditResults $results

    .NOTES
    BGP route propagation must be enabled for ExpressRoute/VPN scenarios
    Orphaned route tables consume resources without serving traffic
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$RouteTables,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuditResults
    )

    Write-AuditLog "Analyzing Route Tables..." -Type Progress

    if ($RouteTables.Count -eq 0) {
        Write-AuditLog "No Route Tables found - skipping analysis" -Type Info
        return
    }

    $orphanedRouteTables = 0
    foreach ($rt in $RouteTables) {
        $hasAttachment = $rt.subnets -and $rt.subnets.Count -gt 0

        if (!$hasAttachment) {
            $orphanedRouteTables++
            Add-AuditIssue -Severity "Low" -Category "Route Table" -Title "Orphaned Route Table" `
                -Description "Route Table '$($rt.name)' is not attached to any subnet" `
                -ResourceName $rt.name -ResourceType "Route Table" -SubscriptionId $rt.subscriptionId `
                -Remediation "Delete Route Table if not needed or attach to subnet" `
                -AuditResults $AuditResults
        }

        if ($rt.provisioningState -ne "Succeeded") {
            Add-AuditIssue -Severity "High" -Category "Route Table" -Title "Route Table provisioning failed" `
                -Description "Route Table '$($rt.name)' is in provisioning state: $($rt.provisioningState)" `
                -ResourceName $rt.name -ResourceType "Route Table" -SubscriptionId $rt.subscriptionId `
                -Remediation "Check for policy violations. Re-create if necessary." `
                -AuditResults $AuditResults
        }

        if ($rt.disableBgpRoutePropagation -eq $true -and $rt.subnets -and $rt.subnets.Count -gt 0) {
            Add-AuditIssue -Severity "Medium" -Category "Route Table" -Title "BGP route propagation disabled" `
                -Description "Route Table '$($rt.name)' has BGP route propagation disabled. ExpressRoute/VPN routes will not propagate." `
                -ResourceName $rt.name -ResourceType "Route Table" -SubscriptionId $rt.subscriptionId `
                -Remediation "Enable BGP route propagation unless intentionally blocking routes" `
                -AuditResults $AuditResults
        }
    }
}

Export-ModuleMember -Function Test-IPAddressOverlap, Get-SubnetUtilization, Add-AuditIssue, Test-VNetProvisioningState, Test-CIDROverlap, Get-IPv6VNets, Invoke-ParallelIPOverlapCheck, Invoke-SequentialIPOverlapCheck, Test-IPAddressOverlaps, Test-VNetPeerings, Test-PrivateDNSZones, Test-VNetLinks, Test-PrivateEndpoints, Test-SubnetUtilization, Test-NetworkSecurityGroups, Test-RouteTables
