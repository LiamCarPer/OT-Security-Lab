BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $repoRoot 'powershell/OTSec/OTSec.psd1') -Force
}

Describe 'Modbus/TCP frame encoding' {
    It 'encodes FC6 with the canonical MBAP header' {
        $frame = ConvertTo-OTModbusFrame -FunctionCode 6 -UnitId 1 -Register 1 -Value 42
        [System.BitConverter]::ToString($frame) |
            Should -Be '00-01-00-00-00-06-01-06-00-01-00-2A'
    }

    It 'encodes FC3 with a register count' {
        $frame = ConvertTo-OTModbusFrame -FunctionCode 3 -Register 0 -Quantity 7
        [System.BitConverter]::ToString($frame) |
            Should -Be '00-01-00-00-00-06-01-03-00-00-00-07'
    }

    It 'encodes FC16 with multiple values' {
        $frame = ConvertTo-OTModbusFrame -FunctionCode 16 -Register 0 -Values 1, 2
        [System.BitConverter]::ToString($frame) |
            Should -Be '00-01-00-00-00-0B-01-10-00-00-00-02-04-00-01-00-02'
    }

    It 'rejects FC16 without values' {
        { ConvertTo-OTModbusFrame -FunctionCode 16 -Register 0 } | Should -Throw
    }

    It 'rejects an out-of-range register' {
        { ConvertTo-OTModbusFrame -FunctionCode 6 -Register 65536 -Value 1 } | Should -Throw
    }
}

Describe 'Modbus response parsing' {
    It 'parses a normal FC6 echo' {
        $frame = [byte[]](0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x2A)
        $parsed = ConvertFrom-OTModbusResponse -Frame $frame
        $parsed.FunctionCode | Should -Be 6
        $parsed.IsException | Should -BeFalse
        $parsed.UnitId | Should -Be 1
    }

    It 'parses a Modbus exception response' {
        $frame = [byte[]](0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x02)
        $parsed = ConvertFrom-OTModbusResponse -Frame $frame
        $parsed.IsException | Should -BeTrue
        $parsed.ExceptionCode | Should -Be 2
    }

    It 'parses FC3 register values' {
        $frame = [byte[]](0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x03, 0x06, 0x00, 0x01, 0x00, 0x2A, 0x00, 0x5F)
        $parsed = ConvertFrom-OTModbusResponse -Frame $frame
        ($parsed.Values -join ',') | Should -Be '1,42,95'
    }
}

Describe 'Lab safety guard' {
    It 'refuses to run without -AllowLab' {
        { Invoke-OTAdversaryScenario -Target 172.21.0.10 } | Should -Throw '*AllowLab*'
    }

    It 'refuses a public target even with -AllowLab' {
        { Invoke-OTAdversaryScenario -Target 8.8.8.8 -AllowLab } | Should -Throw '*outside*'
    }
}

Describe 'Loki response parsing' {
    It 'counts alert types and sources' {
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                result = @(
                    [pscustomobject]@{
                        stream = @{ job = 'ot_alerts' }
                        values = @(
                            @('1', '{"alert_type":"CROSS_ZONE_VIOLATION","source_ip":"172.24.0.10"}'),
                            @('2', '{"alert_type":"UNAUTHORIZED_MODBUS_WRITE","source_ip":"172.24.0.10"}'),
                            @('3', '{"alert_type":"CROSS_ZONE_VIOLATION","source_ip":"172.24.0.30"}')
                        )
                    }
                )
            }
        }
        $summary = ConvertFrom-OTLokiResponse -Response $response
        $summary.Total | Should -Be 3
        ($summary.ByType | Where-Object Type -eq 'CROSS_ZONE_VIOLATION').Count | Should -Be 2
        ($summary.BySource | Where-Object Source -eq '172.24.0.10').Count | Should -Be 2
    }

    It 'ignores non-JSON lines' {
        $response = [pscustomobject]@{
            data = [pscustomobject]@{
                result = @(
                    [pscustomobject]@{
                        values = @(@('1', 'not-json'), @('2', '{"alert_type":"C2_BEACON"}'))
                    }
                )
            }
        }
        (ConvertFrom-OTLokiResponse -Response $response).Total | Should -Be 1
    }
}

Describe 'Caldera operation body' {
    It 'contains the schema fields Caldera requires' {
        $body = ConvertTo-OTCalderaOperationBody -Name 'test' -AdversaryId 'adversary-1'
        $body.name | Should -Be 'test'
        $body.adversary.adversary_id | Should -Be 'adversary-1'
        $body.planner.id | Should -Be 'atomic'
        $body.source.id | Should -Be 'basic'
        $body.state | Should -Be 'running'
    }
}

Describe 'Detection coverage report' {
    It 'finds the committed Sigma rules and their ICS techniques' {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $coverage = @(Get-OTDetectionCoverage -RepoRoot $repoRoot)
        $coverage.Count | Should -BeGreaterOrEqual 5
        ($coverage | Where-Object { $_.Techniques -contains 'T0831' }).Count | Should -BeGreaterThan 0
    }
}
