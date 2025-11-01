@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        'PSUseSingularNouns'
    )

    Rules = @{
        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }
        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }
    }
}
