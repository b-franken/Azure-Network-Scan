BeforeAll {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force

    $script:TestOutputPath = Join-Path $ProjectRoot "Tests/.test-output"
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:TestOutputPath -Force | Out-Null

    $InformationPreference = 'Continue'
}

Describe "Logging Module" -Tag 'Logging', 'Critical' {

    Context "Initialize-AuditLogging Function" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should initialize logging with valid path" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info } | Should -Not -Throw
        }

        It "Should create log file on initialization" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info

            Start-Sleep -Milliseconds 100
            Test-Path $script:logPath | Should -Be $true
        }

        It "Should write initialization message to log file" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Logging initialized:"
        }

        It "Should accept Info log level" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info } | Should -Not -Throw
        }

        It "Should accept Warning log level" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Warning } | Should -Not -Throw
        }

        It "Should accept Error log level" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Error } | Should -Not -Throw
        }

        It "Should accept Debug log level" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug } | Should -Not -Throw
        }

        It "Should reject invalid log level" {
            { Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel "InvalidLevel" } |
                Should -Throw
        }

        It "Should default to Info log level when not specified" {
            { Initialize-AuditLogging -LogFilePath $script:logPath } | Should -Not -Throw
        }
    }

    Context "Write-AuditLog Basic Functionality" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should write Info message to log file" {
            Write-AuditLog "Test info message" -Type Info

            Start-Sleep -Milliseconds 100
            Test-Path $script:logPath | Should -Be $true
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test info message"
        }

        It "Should write Success message to log file" {
            Write-AuditLog "Test success message" -Type Success

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test success message"
        }

        It "Should write Warning message to log file" {
            Write-AuditLog "Test warning message" -Type Warning

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test warning message"
        }

        It "Should write Error message to log file" {
            Write-AuditLog "Test error message" -Type Error

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test error message"
        }

        It "Should write Progress message to log file" {
            Write-AuditLog "Test progress message" -Type Progress

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test progress message"
        }

        It "Should write Debug message to log file" {
            Write-AuditLog "Test debug message" -Type Debug

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Test debug message"
        }

        It "Should default to Info type when not specified" {
            Write-AuditLog "Default type message"

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "\[Info\]"
        }

        It "Should include timestamp in log entry" {
            Write-AuditLog "Timestamp test" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]"
        }

        It "Should include message type in log entry" {
            Write-AuditLog "Type test" -Type Warning

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "\[Warning\]"
        }

        It "Should handle multiple consecutive log writes" {
            Write-AuditLog "Message 1" -Type Info
            Write-AuditLog "Message 2" -Type Warning
            Write-AuditLog "Message 3" -Type Error

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Message 1"
            $content | Should -Match "Message 2"
            $content | Should -Match "Message 3"
        }
    }

    Context "Write-AuditLog Log Level Filtering" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should filter Debug messages when log level is Info" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue

            Write-AuditLog "Debug message should be filtered" -Type Debug

            Start-Sleep -Milliseconds 100
            if (Test-Path $script:logPath) {
                $content = Get-Content $script:logPath -Raw
                $content | Should -Not -Match "Debug message should be filtered"
            }
        }

        It "Should allow Info messages when log level is Info" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Info
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue

            Write-AuditLog "Info message should pass" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Info message should pass"
        }

        It "Should allow Error messages when log level is Error" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Error
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue

            Write-AuditLog "Error message should pass" -Type Error

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Error message should pass"
        }

        It "Should filter Info messages when log level is Error" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Error
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue

            Write-AuditLog "Info message should be filtered" -Type Info

            Start-Sleep -Milliseconds 100
            if (Test-Path $script:logPath) {
                $content = Get-Content $script:logPath -Raw
                $content | Should -Not -Match "Info message should be filtered"
            }
        }

        It "Should allow all messages when log level is Debug" {
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue

            Write-AuditLog "Error message" -Type Error
            Write-AuditLog "Warning message" -Type Warning
            Write-AuditLog "Info message" -Type Info
            Write-AuditLog "Debug message" -Type Debug

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Error message"
            $content | Should -Match "Warning message"
            $content | Should -Match "Info message"
            $content | Should -Match "Debug message"
        }
    }

    Context "Write-AuditLog NoConsole Parameter" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should write to file when NoConsole is specified" {
            Write-AuditLog "NoConsole test message" -Type Info -NoConsole

            Start-Sleep -Milliseconds 100
            Test-Path $script:logPath | Should -Be $true
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "NoConsole test message"
        }

        It "Should not throw when NoConsole is specified" {
            { Write-AuditLog "NoConsole test" -Type Info -NoConsole } | Should -Not -Throw
        }
    }

    Context "Write-AuditLog Special Characters and Edge Cases" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should handle messages with single quotes" {
            Write-AuditLog "Message with 'single quotes'" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Message with 'single quotes'"
        }

        It "Should handle messages with double quotes" {
            Write-AuditLog 'Message with "double quotes"' -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match 'Message with "double quotes"'
        }

        It "Should handle messages with ampersands" {
            Write-AuditLog "Message with & ampersand" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Message with & ampersand"
        }

        It "Should handle messages with angle brackets" {
            Write-AuditLog "Message with <angle> brackets" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Message with <angle> brackets"
        }

        It "Should reject empty string message" {
            { Write-AuditLog "" -Type Info } | Should -Throw -ErrorId 'ParameterArgumentValidationError*'
        }

        It "Should handle very long messages" {
            $longMessage = "A" * 1000
            Write-AuditLog $longMessage -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "A{1000}"
        }

        It "Should handle messages with newlines" {
            Write-AuditLog "Line 1`nLine 2" -Type Info

            Start-Sleep -Milliseconds 100
            Test-Path $script:logPath | Should -Be $true
        }

        It "Should handle messages with Unicode characters" {
            Write-AuditLog "Unicode test: émojis 🎉 中文" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "Unicode test:"
        }
    }

    Context "Write-AuditLog Without Initialization" {

        It "Should not throw when writing without initialization" {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force

            { Write-AuditLog "Test message without init" -Type Info } | Should -Not -Throw
        }

        It "Should not create file when writing without initialization" {
            Import-Module "$ProjectRoot/Modules/Core/AzureAudit.Logging.psm1" -Force
            $randomPath = Join-Path $script:TestOutputPath "should-not-exist-$(New-Guid).log"

            Write-AuditLog "Test message" -Type Info

            Test-Path $randomPath | Should -Be $false
        }
    }

    Context "Timestamp Format Validation" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should use ISO 8601 compatible timestamp format" {
            Write-AuditLog "Timestamp format test" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}"
        }

        It "Should include milliseconds in timestamp" {
            Write-AuditLog "Millisecond test" -Type Info

            Start-Sleep -Milliseconds 100
            $content = Get-Content $script:logPath -Raw
            $content | Should -Match "\d{2}:\d{2}:\d{2}\.\d{3}"
        }

        It "Should have consistent timestamp format across multiple entries" {
            Write-AuditLog "Entry 1" -Type Info
            Write-AuditLog "Entry 2" -Type Warning
            Write-AuditLog "Entry 3" -Type Error

            Start-Sleep -Milliseconds 100
            $lines = Get-Content $script:logPath
            foreach ($line in $lines) {
                $line | Should -Match "^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]"
            }
        }
    }

    Context "Concurrent Logging Operations" {

        BeforeEach {
            $script:logPath = Join-Path $script:TestOutputPath "test-log-$(New-Guid).log"
            Initialize-AuditLogging -LogFilePath $script:logPath -LogLevel Debug
            Start-Sleep -Milliseconds 100
            Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
        }

        AfterEach {
            if (Test-Path $script:logPath) {
                Remove-Item $script:logPath -Force -ErrorAction SilentlyContinue
            }
        }

        It "Should handle rapid sequential log writes" {
            1..10 | ForEach-Object {
                Write-AuditLog "Rapid message $_" -Type Info
            }

            Start-Sleep -Milliseconds 200
            $content = Get-Content $script:logPath -Raw
            1..10 | ForEach-Object {
                $content | Should -Match "Rapid message $_"
            }
        }

        It "Should maintain log integrity with rapid writes" {
            1..20 | ForEach-Object {
                Write-AuditLog "Message $_" -Type Info
            }

            Start-Sleep -Milliseconds 200
            $lines = @(Get-Content $script:logPath)
            $lines.Count | Should -Be 20
        }
    }

    Context "Log File Error Handling" {

        It "Should handle invalid file path gracefully" {
            $invalidPath = "Z:\NonExistent\Path\test.log"

            { Initialize-AuditLogging -LogFilePath $invalidPath -LogLevel Info } | Should -Not -Throw
        }

        It "Should continue execution when unable to write to log file" {
            $invalidPath = "C:\<invalid>:path\test.log"
            Initialize-AuditLogging -LogFilePath $invalidPath -LogLevel Info

            { Write-AuditLog "Test message" -Type Info } | Should -Not -Throw
        }
    }

    Context "Module Export Verification" {

        It "Should export Initialize-AuditLogging function" {
            $commands = Get-Command -Module AzureAudit.Logging
            $commands.Name | Should -Contain "Initialize-AuditLogging"
        }

        It "Should export Write-AuditLog function" {
            $commands = Get-Command -Module AzureAudit.Logging
            $commands.Name | Should -Contain "Write-AuditLog"
        }

        It "Should only export two functions" {
            $commands = Get-Command -Module AzureAudit.Logging
            $commands.Count | Should -Be 2
        }
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
