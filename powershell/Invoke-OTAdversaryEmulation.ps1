#Requires -Version 7.2
<#
.SYNOPSIS
    Run a bounded PowerShell adversary scenario against the OT lab.

.DESCRIPTION
    This is the PowerShell counterpart to the Python/Scapy scenarios in
    lab-environment/attacker. It is intended to run inside the isolated lab
    (the ot_powershell host in the Supervisory zone) and refuses any target
    outside 172.21.0.0/24.

.EXAMPLE
    pwsh -File ./Invoke-OTAdversaryEmulation.ps1 `
        -Scenario UnauthorizedWrite -Target 172.21.0.10 -AllowLab

.EXAMPLE
    pwsh -File ./Invoke-OTAdversaryEmulation.ps1 `
        -Scenario Recon -Target 172.21.0.10 -AllowLab
#>
[CmdletBinding()]
param(
    [ValidateSet('UnauthorizedWrite', 'Recon')]
    [string]$Scenario = 'UnauthorizedWrite',

    [string]$Target = '172.21.0.10',

    [ValidateRange(0, 65535)]
    [int]$Register = 1,

    [ValidateRange(0, 65535)]
    [int]$TestValue = 42,

    [switch]$AllowLab,

    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'OTSec/OTSec.psd1'
Import-Module $modulePath -Force

$result = Invoke-OTAdversaryScenario -Scenario $Scenario -Target $Target `
    -Register $Register -TestValue $TestValue -AllowLab:$AllowLab `
    -EvidencePath $EvidencePath -Confirm:$false

$result | ConvertTo-Json -Depth 8
if (-not $result.Success) {
    exit 1
}
