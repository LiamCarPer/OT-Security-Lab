#Requires -Version 7.2
Set-StrictMode -Version Latest

function ConvertTo-OTModbusFrame {
    <#
    .SYNOPSIS
        Build a Modbus/TCP frame for FC3, FC6 or FC16.
    .DESCRIPTION
        The lab uses the canonical register map in plc/register-map.md. This
        helper keeps the MBAP and PDU encoding in one place so the PowerShell
        adversary scenarios and the Pester tests exercise the same bytes.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(3, 6, 16)]
        [int]$FunctionCode,

        [ValidateRange(0, 255)]
        [int]$UnitId = 1,

        [ValidateRange(0, 65535)]
        [int]$Register = 0,

        [ValidateRange(0, 65535)]
        [int]$Value = 0,

        [int[]]$Values,

        [ValidateRange(1, 125)]
        [int]$Quantity = 1
    )

    $pdu = [System.Collections.Generic.List[byte]]::new()

    switch ($FunctionCode) {
        3 {
            $pdu.Add([byte]0x03)
            $pdu.Add([byte](($Register -shr 8) -band 0xFF))
            $pdu.Add([byte]($Register -band 0xFF))
            $pdu.Add([byte](($Quantity -shr 8) -band 0xFF))
            $pdu.Add([byte]($Quantity -band 0xFF))
        }
        6 {
            $pdu.Add([byte]0x06)
            $pdu.Add([byte](($Register -shr 8) -band 0xFF))
            $pdu.Add([byte]($Register -band 0xFF))
            $pdu.Add([byte](($Value -shr 8) -band 0xFF))
            $pdu.Add([byte]($Value -band 0xFF))
        }
        16 {
            if (-not $Values -or $Values.Count -eq 0) {
                throw 'FC16 requires at least one value in -Values.'
            }
            if ($Values.Count -gt 123) {
                throw 'FC16 supports at most 123 register values.'
            }
            $quantity = $Values.Count
            $pdu.Add([byte]0x10)
            $pdu.Add([byte](($Register -shr 8) -band 0xFF))
            $pdu.Add([byte]($Register -band 0xFF))
            $pdu.Add([byte](($quantity -shr 8) -band 0xFF))
            $pdu.Add([byte]($quantity -band 0xFF))
            $pdu.Add([byte]($quantity * 2))
            foreach ($item in $Values) {
                if ($item -lt 0 -or $item -gt 65535) {
                    throw "Register value $item is outside the unsigned 16-bit range."
                }
                $pdu.Add([byte](($item -shr 8) -band 0xFF))
                $pdu.Add([byte]($item -band 0xFF))
            }
        }
    }

    $length = $pdu.Count + 1
    $frame = [System.Collections.Generic.List[byte]]::new()
    $frame.Add([byte]0x00)
    $frame.Add([byte]0x01)
    $frame.Add([byte]0x00)
    $frame.Add([byte]0x00)
    $frame.Add([byte](($length -shr 8) -band 0xFF))
    $frame.Add([byte]($length -band 0xFF))
    $frame.Add([byte]$UnitId)
    $frame.AddRange($pdu)

    return ,([byte[]]$frame.ToArray())
}

function ConvertFrom-OTModbusResponse {
    <#
    .SYNOPSIS
        Parse a Modbus/TCP response frame into a typed object.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Frame
    )

    if ($Frame.Count -lt 9) {
        throw "A Modbus response needs at least 9 bytes; got $($Frame.Count)."
    }

    $transactionId = ([int]$Frame[0] -shl 8) -bor [int]$Frame[1]
    $protocolId = ([int]$Frame[2] -shl 8) -bor [int]$Frame[3]
    $length = ([int]$Frame[4] -shl 8) -bor [int]$Frame[5]
    $unitId = [int]$Frame[6]
    $functionCode = [int]$Frame[7]
    $isException = ($functionCode -band 0x80) -ne 0
    $exceptionCode = $null
    $byteCount = $null
    $values = @()

    if ($isException) {
        if ($Frame.Count -lt 9) {
            throw 'Exception response is missing the exception code.'
        }
        $exceptionCode = [int]$Frame[8]
    }
    elseif ($functionCode -eq 3) {
        $byteCount = [int]$Frame[8]
        if (($Frame.Count - 9) -lt $byteCount) {
            throw "FC3 response declares $byteCount data bytes but only $($Frame.Count - 9) are present."
        }
        for ($index = 0; $index -lt $byteCount; $index += 2) {
            $high = [int]$Frame[9 + $index]
            $low = [int]$Frame[10 + $index]
            $values += (($high -shl 8) -bor $low)
        }
    }

    [pscustomobject]@{
        TransactionId = $transactionId
        ProtocolId    = $protocolId
        Length        = $length
        UnitId        = $unitId
        FunctionCode  = $functionCode
        IsException   = $isException
        ExceptionCode = $exceptionCode
        ByteCount     = $byteCount
        Values        = $values
        Raw           = ([System.BitConverter]::ToString($Frame))
    }
}

function Read-OTStream {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Count
    )

    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            throw "The remote endpoint closed the connection after $offset of $Count bytes."
        }
        $offset += $read
    }
    return ,$buffer
}

function Invoke-OTModbusRequest {
    <#
    .SYNOPSIS
        Send a raw Modbus/TCP frame and parse the response.
    .DESCRIPTION
        Returns a result object even when the connection or response fails, so
        adversary scenarios can record the attempt without masking the failure.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [ValidateRange(1, 65535)]
        [int]$Port = 502,

        [Parameter(Mandatory)]
        [byte[]]$Frame,

        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 3000
    )

    $parsedTarget = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$parsedTarget)) {
        throw "Target '$Target' is not an IPv4 address. Use the lab's static addresses."
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = [ordered]@{
        Target        = $Target
        Port          = $Port
        FunctionCode  = $null
        Success       = $false
        ExceptionCode = $null
        Values        = @()
        RawResponse   = $null
        DurationMs    = 0
        Error         = $null
    }

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($Target, $Port)
        if (-not $connect.Wait($TimeoutMs)) {
            throw "Connection to ${Target}:${Port} timed out after ${TimeoutMs} ms."
        }

        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs
        $stream.Write($Frame, 0, $Frame.Length)
        $stream.Flush()

        $header = Read-OTStream -Stream $stream -Count 7
        $mbapLength = ([int]$header[4] -shl 8) -bor [int]$header[5]
        if ($mbapLength -lt 2) {
            throw "Invalid MBAP length $mbapLength."
        }
        $pdu = Read-OTStream -Stream $stream -Count ($mbapLength - 1)
        $response = [byte[]]($header + $pdu)
        $parsed = ConvertFrom-OTModbusResponse -Frame $response

        $result.FunctionCode = $parsed.FunctionCode
        $result.ExceptionCode = $parsed.ExceptionCode
        $result.Values = $parsed.Values
        $result.RawResponse = $parsed.Raw
        $result.Success = -not $parsed.IsException
        if ($parsed.IsException) {
            $result.Error = "Modbus exception code $($parsed.ExceptionCode)."
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        $client.Dispose()
        $stopwatch.Stop()
        $result.DurationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
    }

    [pscustomobject]$result
}

function Invoke-OTModbusWrite {
    <#
    .SYNOPSIS
        Write one holding register with Modbus FC6.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateRange(0, 65535)]
        [int]$Register,

        [Parameter(Mandatory)]
        [ValidateRange(0, 65535)]
        [int]$Value,

        [ValidateRange(0, 255)]
        [int]$UnitId = 1,

        [ValidateRange(1, 65535)]
        [int]$Port = 502,

        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 3000
    )

    $frame = ConvertTo-OTModbusFrame -FunctionCode 6 -UnitId $UnitId -Register $Register -Value $Value
    if ($PSCmdlet.ShouldProcess("${Target}:${Port} HR${Register}", "Write value $Value")) {
        Invoke-OTModbusRequest -Target $Target -Port $Port -Frame $frame -TimeoutMs $TimeoutMs
    }
}

function Get-OTProcessState {
    <#
    .SYNOPSIS
        Read the canonical intake register map from PLC-01.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Target = '172.21.0.10',
        [ValidateRange(1, 65535)]
        [int]$Port = 502,
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 3000
    )

    $frame = ConvertTo-OTModbusFrame -FunctionCode 3 -Register 0 -Quantity 7
    $response = Invoke-OTModbusRequest -Target $Target -Port $Port -Frame $frame -TimeoutMs $TimeoutMs
    $state = [ordered]@{
        Target            = $Target
        Success           = $response.Success
        Valve             = $null
        PumpSpeed         = $null
        TankLevel         = $null
        OverflowInterlock = $null
        Values            = $response.Values
        Error             = $response.Error
    }
    if ($response.Success -and $response.Values.Count -ge 6) {
        $state.Valve = $response.Values[0]
        $state.PumpSpeed = $response.Values[1]
        $state.TankLevel = $response.Values[5]
        $state.OverflowInterlock = $response.Values[6]
    }
    [pscustomobject]$state
}

function Test-OTConduit {
    <#
    .SYNOPSIS
        Test whether a TCP conduit is reachable from the current host.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 2000
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    $open = $false
    $errorMessage = $null
    try {
        $connect = $client.ConnectAsync($Target, $Port)
        $open = $connect.Wait($TimeoutMs)
        if (-not $open) {
            $errorMessage = "Connection timed out after ${TimeoutMs} ms."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
    }
    finally {
        $client.Dispose()
        $stopwatch.Stop()
    }

    [pscustomobject]@{
        Target     = $Target
        Port       = $Port
        Open       = $open
        DurationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
        Error      = $errorMessage
    }
}

function Invoke-OTAdversaryScenario {
    <#
    .SYNOPSIS
        Run a bounded PowerShell adversary scenario against the lab.
    .DESCRIPTION
        The scenario refuses targets outside the lab Control subnet unless the
        caller explicitly supplies -AllowLab. It never touches a public address.
        UnauthorizedWrite reads the original register, writes a test value and
        restores the original value so the process is left unchanged.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
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

    if (-not $AllowLab) {
        throw 'Refusing to run an adversary scenario without -AllowLab. This switch confirms the target is the isolated lab.'
    }
    $parsedTarget = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$parsedTarget)) {
        throw "Target '$Target' is not an IPv4 address."
    }
    if (-not $Target.StartsWith('172.21.')) {
        throw "Target '$Target' is outside the lab Control subnet 172.21.0.0/24."
    }

    $started = Get-Date
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = [ordered]@{
        Scenario   = $Scenario
        Target     = $Target
        StartedAt  = $started.ToUniversalTime().ToString('o')
        AllowLab   = [bool]$AllowLab
        Steps      = @()
        Success    = $false
        DurationMs = 0
        Error      = $null
    }

    try {
        switch ($Scenario) {
            'Recon' {
                $ports = 502, 102, 20000, 4840, 8443
                $probes = foreach ($port in $ports) {
                    $probe = Test-OTConduit -Target $Target -Port $port -TimeoutMs 1000
                    [pscustomobject]@{
                        Port       = $port
                        Open       = $probe.Open
                        DurationMs = $probe.DurationMs
                        Error      = $probe.Error
                    }
                }
                $result.Steps = @($probes)
                $result.Success = $true
            }
            'UnauthorizedWrite' {
                if (-not $PSCmdlet.ShouldProcess("${Target} HR${Register}", "Write test value $TestValue and restore")) {
                    return
                }

                $before = Get-OTProcessState -Target $Target
                if (-not $before.Success) {
                    throw "Could not read the process image: $($before.Error)"
                }
                $originalValue = if ($Register -eq 1) { $before.PumpSpeed } else { $null }
                if ($null -eq $originalValue) {
                    throw "The scenario only restores HR1 (intake pump speed); got HR$Register."
                }

                $write = Invoke-OTModbusWrite -Target $Target -Register $Register -Value $TestValue -Confirm:$false
                $after = Get-OTProcessState -Target $Target
                $restore = Invoke-OTModbusWrite -Target $Target -Register $Register -Value $originalValue -Confirm:$false

                $result.Steps = @(
                    [pscustomobject]@{ Step = 'ReadBefore'; Success = $before.Success; Values = $before.Values },
                    [pscustomobject]@{ Step = 'Write'; Success = $write.Success; Value = $TestValue; Error = $write.Error },
                    [pscustomobject]@{ Step = 'ReadAfter'; Success = $after.Success; Values = $after.Values },
                    [pscustomobject]@{ Step = 'Restore'; Success = $restore.Success; Value = $originalValue; Error = $restore.Error }
                )
                $result.Success = $write.Success -and $restore.Success
                if (-not $result.Success) {
                    $result.Error = "Write acknowledged: $($write.Success); restore acknowledged: $($restore.Success)."
                }
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        $stopwatch.Stop()
        $result.DurationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
    }

    if ($EvidencePath) {
        $directory = Split-Path -Parent $EvidencePath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding utf8
    }

    [pscustomobject]$result
}

function ConvertFrom-OTLokiResponse {
    <#
    .SYNOPSIS
        Parse a Loki query_range response into an alert summary.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Response
    )

    $alerts = [System.Collections.Generic.List[object]]::new()
    $streams = @()
    if ($null -ne $Response -and $null -ne $Response.data -and $null -ne $Response.data.result) {
        $streams = @($Response.data.result)
    }

    foreach ($stream in $streams) {
        foreach ($entry in @($stream.values)) {
            if ($null -eq $entry -or @($entry).Count -lt 2) {
                continue
            }
            $line = [string]@($entry)[1]
            try {
                $alerts.Add(($line | ConvertFrom-Json -ErrorAction Stop))
            }
            catch {
                continue
            }
        }
    }

    $byType = $alerts | Group-Object -Property alert_type | Sort-Object Count -Descending
    $bySource = $alerts | Where-Object { $_.PSObject.Properties.Name -contains 'source_ip' } |
        Group-Object -Property source_ip | Sort-Object Count -Descending

    [pscustomobject]@{
        Total    = $alerts.Count
        ByType   = @($byType | ForEach-Object { [pscustomobject]@{ Type = $_.Name; Count = $_.Count } })
        BySource = @($bySource | ForEach-Object { [pscustomobject]@{ Source = $_.Name; Count = $_.Count } })
        Alerts   = @($alerts)
    }
}

function Get-OTAlertSummary {
    <#
    .SYNOPSIS
        Query Loki for the lab's alert stream and return a summary.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$LokiUrl = 'http://localhost:3100',
        [ValidateRange(1, 1440)]
        [int]$WindowMinutes = 60,
        [string]$AlertType,
        [switch]$AsMarkdown
    )

    $endNs = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) * 1000000000
    $startNs = $endNs - ([long]$WindowMinutes * 60 * 1000000000)
    $query = [uri]::EscapeDataString('{job="ot_alerts"}')
    $uri = "${LokiUrl}/loki/api/v1/query_range?query=${query}&start=${startNs}&end=${endNs}&limit=5000"
    $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30
    $summary = ConvertFrom-OTLokiResponse -Response $response

    if ($AlertType) {
        $filtered = @($summary.Alerts | Where-Object { $_.alert_type -eq $AlertType })
        $summary = [pscustomobject]@{
            Total    = $filtered.Count
            ByType   = @($filtered | Group-Object -Property alert_type | ForEach-Object {
                    [pscustomobject]@{ Type = $_.Name; Count = $_.Count }
                })
            BySource = @($filtered | Group-Object -Property source_ip | ForEach-Object {
                    [pscustomobject]@{ Source = $_.Name; Count = $_.Count }
                })
            Alerts   = $filtered
        }
    }

    if ($AsMarkdown) {
        $lines = @(
            "| Alert type | Count |",
            "| :--- | ---: |"
        )
        foreach ($row in $summary.ByType) {
            $lines += "| ``$($row.Type)`` | $($row.Count) |"
        }
        $lines += "| **Total** | **$($summary.Total)** |"
        $lines
    }
    else {
        $summary
    }
}

function ConvertTo-OTCalderaOperationBody {
    <#
    .SYNOPSIS
        Build the JSON body for a Caldera v2 operation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$AdversaryId,

        [string]$Group = 'red',
        [string]$PlannerId = 'atomic',
        [string]$SourceId = 'basic'
    )

    @{
        name       = $Name
        adversary  = @{ adversary_id = $AdversaryId }
        planner    = @{ id = $PlannerId }
        source     = @{ id = $SourceId }
        group      = $Group
        state      = 'running'
        auto_close = $true
    }
}

function Invoke-OTCalderaOperation {
    <#
    .SYNOPSIS
        Start a Caldera operation, wait for completion and capture evidence.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$CalderaUrl = 'http://localhost:8888',
        [string]$ApiKey = $env:CALDERA_API_KEY,
        [string]$AdversaryName = 'OT External Adversary',
        [string]$AdversaryId,
        [string]$Group = 'red',
        [string]$Name = "OT Caldera Operation $(Get-Date -Format 'yyyyMMdd-HHmmss')",
        [ValidateRange(1, 120)]
        [int]$TimeoutMinutes = 10,
        [ValidateRange(1, 60)]
        [int]$PollSeconds = 5,
        [string]$LokiUrl = 'http://localhost:3100',
        [string]$EvidencePath
    )

    if (-not $ApiKey) {
        throw 'A Caldera API key is required. Pass -ApiKey or set CALDERA_API_KEY.'
    }
    $headers = @{ KEY = $ApiKey }

    $agents = Invoke-RestMethod -Uri "${CalderaUrl}/api/v2/agents" -Headers $headers -Method Get -TimeoutSec 30
    if (-not $agents) {
        throw 'No Caldera agents have checked in. Start the attacker Sandcat agent before running an operation.'
    }

    if (-not $AdversaryId) {
        $adversaries = Invoke-RestMethod -Uri "${CalderaUrl}/api/v2/adversaries" -Headers $headers -Method Get -TimeoutSec 30
        $match = $adversaries | Where-Object { $_.name -eq $AdversaryName } | Select-Object -First 1
        if (-not $match) {
            throw "Caldera adversary '$AdversaryName' was not found. Import the ot-lab plugin or pass -AdversaryId."
        }
        $AdversaryId = $match.adversary_id
    }

    $body = ConvertTo-OTCalderaOperationBody -Name $Name -AdversaryId $AdversaryId -Group $Group
    $created = Invoke-RestMethod -Uri "${CalderaUrl}/api/v2/operations" -Headers $headers -Method Post `
        -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 6) -TimeoutSec 30
    $operationId = $created.id
    if (-not $operationId) {
        throw 'Caldera did not return an operation id.'
    }

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $operation = $created
    do {
        Start-Sleep -Seconds $PollSeconds
        $operation = Invoke-RestMethod -Uri "${CalderaUrl}/api/v2/operations/${operationId}" -Headers $headers -Method Get -TimeoutSec 30
        Write-Verbose "Caldera operation ${operationId} state: $($operation.state)"
    } while ($operation.state -in @('running', 'paused', 'cleanup') -and (Get-Date) -lt $deadline)

    $links = @()
    try {
        $links = Invoke-RestMethod -Uri "${CalderaUrl}/api/v2/operations/${operationId}/links" -Headers $headers -Method Get -TimeoutSec 30
    }
    catch {
        Write-Verbose "Could not retrieve Caldera links: $($_.Exception.Message)"
    }
    $linkItems = @($links | ForEach-Object {
            [pscustomobject]@{
                Ability   = $_.ability.name
                Technique = $_.ability.technique_id
                Status    = $_.status
                Command   = $_.command
            }
        })

    $alertSummary = $null
    try {
        $summary = Get-OTAlertSummary -LokiUrl $LokiUrl -WindowMinutes 5
        $alertSummary = [pscustomobject]@{
            Total    = $summary.Total
            ByType   = $summary.ByType
            BySource = $summary.BySource
        }
    }
    catch {
        Write-Verbose "Could not query Loki: $($_.Exception.Message)"
    }

    $result = [ordered]@{
        CalderaUrl    = $CalderaUrl
        OperationId   = $operationId
        Name          = $Name
        AdversaryId   = $AdversaryId
        Group         = $Group
        State         = $operation.state
        StartedAt     = $operation.start
        Links         = $linkItems
        Alerts        = $alertSummary
        CapturedAt    = (Get-Date).ToUniversalTime().ToString('o')
    }

    if ($EvidencePath) {
        $directory = Split-Path -Parent $EvidencePath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $EvidencePath -Encoding utf8
    }

    [pscustomobject]$result
}

function Get-OTDetectionCoverage {
    <#
    .SYNOPSIS
        Summarise Sigma rules and their ATT&CK for ICS techniques.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
        [switch]$AsMarkdown
    )

    $sigmaDirectory = Join-Path $RepoRoot 'detection/sigma'
    if (-not (Test-Path -LiteralPath $sigmaDirectory)) {
        throw "Sigma directory not found: $sigmaDirectory"
    }

    $coverage = foreach ($file in Get-ChildItem -LiteralPath $sigmaDirectory -Filter '*.yml' | Sort-Object Name) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        $titleMatch = [regex]::Match($text, '(?m)^title:\s*(.+?)\s*$')
        $idMatch = [regex]::Match($text, '(?m)^id:\s*(.+?)\s*$')
        $techniques = [regex]::Matches($text, 'attack\.ics\.(t\d{4}(?:\.\d{3})?)') |
            ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() } | Sort-Object -Unique
        $alertTypes = [regex]::Matches($text, '(?m)^\s*alert_type:\s*([A-Z0-9_]+)') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        [pscustomobject]@{
            File       = $file.Name
            Title      = if ($titleMatch.Success) { $titleMatch.Groups[1].Value } else { '(untitled)' }
            Id         = if ($idMatch.Success) { $idMatch.Groups[1].Value } else { '' }
            Techniques = @($techniques)
            AlertTypes = @($alertTypes)
        }
    }

    if ($AsMarkdown) {
        $lines = @(
            '| Sigma rule | ATT&CK for ICS | Alert types |',
            '| :--- | :--- | :--- |'
        )
        foreach ($row in $coverage) {
            $lines += "| $($row.Title) | $($row.Techniques -join ', ') | $($row.AlertTypes -join ', ') |"
        }
        $lines
    }
    else {
        @($coverage)
    }
}

Export-ModuleMember -Function @(
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
