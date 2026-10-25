#Requires -Version 7.2
<#
.SYNOPSIS
    Report Sigma coverage and, optionally, the live Loki alert summary.

.DESCRIPTION
    Produces a small detection-engineering report without requiring a SIEM
    query. Use -IncludeAlerts to add the live alert summary when Loki is
    reachable.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$LokiUrl = 'http://localhost:3100',
    [switch]$IncludeAlerts,
    [switch]$AsMarkdown,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'OTSec/OTSec.psd1') -Force

$coverage = @(Get-OTDetectionCoverage -RepoRoot $RepoRoot)
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('# Detection Coverage')
$lines.Add('')
$lines.Add('| Sigma rule | ATT&CK for ICS | Alert types |')
$lines.Add('| :--- | :--- | :--- |')
foreach ($row in $coverage) {
    $lines.Add("| $($row.Title) | $($row.Techniques -join ', ') | $($row.AlertTypes -join ', ') |")
}
$lines.Add('')
$lines.Add("Sigma rules: **$($coverage.Count)**")

if ($IncludeAlerts) {
    try {
        $summary = Get-OTAlertSummary -LokiUrl $LokiUrl -WindowMinutes 60
        $lines.Add('')
        $lines.Add('## Live alerts (last 60 minutes)')
        $lines.Add('')
        $lines.Add('| Alert type | Count |')
        $lines.Add('| :--- | ---: |')
        foreach ($row in $summary.ByType) {
            $lines.Add("| ``$($row.Type)`` | $($row.Count) |")
        }
        $lines.Add("| **Total** | **$($summary.Total)** |")
    }
    catch {
        $lines.Add('')
        $lines.Add("Live alert summary unavailable: $($_.Exception.Message)")
    }
}

$report = $lines -join [Environment]::NewLine
if ($OutputPath) {
    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Set-Content -LiteralPath $OutputPath -Value $report -Encoding utf8
    Write-Output "wrote $OutputPath"
}
elseif ($AsMarkdown) {
    Write-Output $report
}
else {
    $coverage | Format-Table -AutoSize
}
