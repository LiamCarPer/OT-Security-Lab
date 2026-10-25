@{
    RootModule        = 'OTSec.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '0f6a8b5c-4f3e-4c2a-9d1b-7e8f0a2c6b41'
    Author            = 'OT Security Lab'
    CompanyName       = 'OT Security Lab'
    Copyright         = '(c) OT Security Lab. MIT licensed.'
    Description       = 'PowerShell toolkit for OT adversary emulation and detection operations.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'ConvertTo-OTModbusFrame',
        'ConvertFrom-OTModbusResponse',
        'Invoke-OTModbusRequest',
        'Invoke-OTModbusWrite',
        'Get-OTProcessState',
        'Test-OTConduit',
        'Invoke-OTAdversaryScenario',
        'ConvertFrom-OTLokiResponse',
        'Get-OTAlertSummary',
        'ConvertTo-OTCalderaOperationBody',
        'Invoke-OTCalderaOperation',
        'Get-OTDetectionCoverage'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('OT', 'ICS', 'Modbus', 'Detection', 'AdversaryEmulation')
            ProjectUri = 'https://github.com/LiamCarPer/OT-Security-Lab'
            LicenseUri = 'https://github.com/LiamCarPer/OT-Security-Lab/blob/main/LICENSE'
        }
    }
}
