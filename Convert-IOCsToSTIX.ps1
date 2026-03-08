<#
.SYNOPSIS
    Converts IOC lists (mixed or typed) to STIX 2.1 indicators for Microsoft Sentinel.

.DESCRIPTION
    Reads one file or all files in a folder (TXT, CSV, JSON).
    Auto-detects indicator type: ipv4-addr, ipv6-addr, domain-name, url, file (hashes),
    email-addr, user-account, windows-registry-key.
    Outputs a single JSON or one file per type, ready to import into Sentinel.
    Compatible with PowerShell 5.1 and 7+.

.NOTES
    STIX 2.1 | Sentinel/Defender TI Import Format
    Version  : 1.0
    Author   : Alex Milla — https://alexmilla.dev
#>

[CmdletBinding()]
param(
    [string]$InputPath   = "",   # File or folder
    [string]$OutputPath  = "",   # Folder for output
    [switch]$SplitByType,        # Create one file per IOC type
    [switch]$NonInteractive      # For pipeline/automation use
)

Set-StrictMode -Off

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
$VERSION     = "2.0"
$CONFIG_FILE = Join-Path $PSScriptRoot "stix_converter_config.json"

# TLP marking-definition IDs (STIX 2.1 / OASIS)
$TLP = @{
    white = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'
    green = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
    amber = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
    red   = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'
}

# STIX object types supported by Sentinel (from template)
$SUPPORTED_TYPES = @('ipv4-addr','ipv6-addr','domain-name','url','file','email-addr','user-account','windows-registry-key')

# Output file names per type
$TYPE_FILENAMES = @{
    'ipv4-addr'            = 'stix_ipv4.json'
    'ipv6-addr'            = 'stix_ipv6.json'
    'domain-name'          = 'stix_domains.json'
    'url'                  = 'stix_urls.json'
    'file'                 = 'stix_hashes.json'
    'email-addr'           = 'stix_emails.json'
    'user-account'         = 'stix_users.json'
    'windows-registry-key' = 'stix_registry.json'
}

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────
$_logFile = ""

function Write-Log {
    param([string]$Msg, [string]$Color = "White", [switch]$NoNewline)
    if ($NoNewline) { Write-Host $Msg -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Msg -ForegroundColor $Color }
    if ($_logFile) {
        $ts = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $_logFile -Value "[$ts] $Msg" -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Write-Sep  { Write-Log "─────────────────────────────────────────" -Color DarkGray }
function Write-Sep2 { Write-Log "=========================================" -Color DarkGray }

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
function Get-DefaultConfig {
    return @{
        OutputFolder   = $PSScriptRoot
        ThreatActor    = ""
        Source         = ""
        Tags           = @()
        Confidence     = 75
        TLPLevel       = "white"
        IndicatorTypes = "malicious-activity"
        ValidDays      = 365
        LogFile        = ""
        # API (stub — fill in to enable uploads)
        API = @{
            Enabled     = $false
            WorkspaceId = ""
            Endpoint    = "https://sentinelus.azure-api.net/workspaces/{workspaceId}/threatintelligenceindicators:upload?api-version=2022-07-01"
            BatchSize   = 100
        }
    }
}

function Load-Config {
    if (Test-Path $CONFIG_FILE) {
        try {
            $raw = Get-Content $CONFIG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
            $cfg = Get-DefaultConfig
            foreach ($k in @('OutputFolder','ThreatActor','Source','Confidence','TLPLevel','IndicatorTypes','ValidDays','LogFile')) {
                if ($null -ne $raw.$k) { $cfg[$k] = $raw.$k }
            }
            if ($raw.Tags)  { $cfg.Tags  = @($raw.Tags)  }
            if ($raw.API)   {
                foreach ($k in @('Enabled','WorkspaceId','Endpoint','BatchSize')) {
                    if ($null -ne $raw.API.$k) { $cfg.API[$k] = $raw.API.$k }
                }
            }
            return $cfg
        } catch {}
    }
    return Get-DefaultConfig
}

function Save-Config([hashtable]$Cfg) {
    try {
        $Cfg | ConvertTo-Json -Depth 5 | Set-Content $CONFIG_FILE -Encoding UTF8
        Write-Log "  [OK] Config saved → $CONFIG_FILE" -Color Green
    } catch {
        Write-Log "  [!] Could not save config: $_" -Color Yellow
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-DETECT IOC TYPE
# ─────────────────────────────────────────────────────────────────────────────
function Get-IOCType {
    param([string]$Value)

    $v = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }

    # Windows registry key
    if ($v -match '^HK(EY_|LM|CU|CR|U|CC)') { return 'windows-registry-key' }

    # Email
    if ($v -match '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$') { return 'email-addr' }

    # URL (must be before domain check)
    if ($v -match '^(https?|ftp|ftps)://') { return 'url' }

    # IPv4 (with optional CIDR)
    if ($v -match '^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$') {
        $octets = ($v -split '/')[0] -split '\.'
        if (($octets | Where-Object { [int]$_ -gt 255 }).Count -eq 0) { return 'ipv4-addr' }
    }

    # IPv6
    if ($v -match '^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/\d{1,3})?$') { return 'ipv6-addr' }

    # Hashes (MD5=32, SHA1=40, SHA256=64, SHA512=128)
    if ($v -match '^[0-9a-fA-F]+$') {
        switch ($v.Length) {
            32  { return 'file' }
            40  { return 'file' }
            64  { return 'file' }
            128 { return 'file' }
        }
    }

    # Domain-name (has at least one dot, valid chars, no spaces)
    if ($v -match '^(?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}$' -and $v -notmatch '\s') {
        return 'domain-name'
    }

    return $null   # Unknown / unsupported
}

function Get-HashAlgorithm([string]$Hash) {
    switch ($Hash.Length) {
        32  { return 'MD5' }
        40  { return 'SHA-1' }
        64  { return 'SHA-256' }
        128 { return 'SHA-512' }
        default { return 'SHA-256' }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  STIX PATTERN BUILDER
# ─────────────────────────────────────────────────────────────────────────────
function New-STIXPattern {
    param([string]$Type, [string]$Value)

    switch ($Type) {
        'ipv4-addr'            { return "[ipv4-addr:value = '$Value']" }
        'ipv6-addr'            { return "[ipv6-addr:value = '$Value']" }
        'domain-name'          { return "[domain-name:value = '$Value']" }
        'url'                  { return "[url:value = '$Value']" }
        'email-addr'           { return "[email-message:sender_ref.value = '$Value']" }
        'user-account'         { return "[user-account:user_id = '$Value']" }
        'windows-registry-key' { return "[windows-registry-key:key = '$Value']" }
        'file' {
            $algo = Get-HashAlgorithm $Value
            switch ($algo) {
                'MD5'     { return "[file:hashes.MD5 = '$Value']" }
                'SHA-1'   { return "[file:hashes.'SHA-1' = '$Value']" }
                'SHA-256' { return "[file:hashes.'SHA-256' = '$Value']" }
                'SHA-512' { return "[file:hashes.'SHA-512' = '$Value']" }
            }
        }
    }
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
#  BUILD ONE STIX INDICATOR OBJECT
# ─────────────────────────────────────────────────────────────────────────────
function New-STIXIndicator {
    param(
        [string]$Type,
        [string]$Value,
        [string]$Source,
        [string]$ThreatActor,
        [string[]]$Tags,
        [int]$Confidence,
        [string]$TLPLevel,
        [string]$IndicatorTypes,
        [int]$ValidDays,
        [string]$ValidFrom = ""
    )

    $now       = [DateTime]::UtcNow
    $nowStr    = $now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $validFrom = if ($ValidFrom) { ConvertTo-UTCDate $ValidFrom } else { $nowStr }
    $validUntil = $now.AddDays($ValidDays).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    $id      = "indicator--$([guid]::NewGuid())"
    $pattern = New-STIXPattern -Type $Type -Value $Value

    # Name: prefer Source, else auto-generate
    $name = if ($Source) { "$Source - $Value" } `
            elseif ($ThreatActor) { "$ThreatActor - $($Type.ToUpper()) - $Value" } `
            else { "$($Type.ToUpper()) - $Value" }

    # Labels = ThreatActor + type + custom tags (deduped)
    $labelSet = [System.Collections.Generic.List[string]]::new()
    if ($ThreatActor) { $labelSet.Add($ThreatActor) }
    $labelSet.Add($Type)
    foreach ($t in $Tags) { if ($t -and -not $labelSet.Contains($t)) { $labelSet.Add($t) } }

    $desc = if ($ThreatActor) { "IOC ($Type) associated with $ThreatActor" } `
            else { "IOC ($Type) from $Source" }

    return [PSCustomObject]@{
        type                = "indicator"
        id                  = $id
        spec_version        = "2.1"
        pattern             = $pattern
        pattern_type        = "stix"
        pattern_version     = "2.1"
        created             = $nowStr
        modified            = $nowStr
        valid_from          = $validFrom
        valid_until         = $validUntil
        name                = $name
        description         = $desc
        indicator_types     = @($IndicatorTypes)
        # created_by_ref omitted — empty string fails STIX validation in Sentinel
        kill_chain_phases   = @()
        revoked             = $false
        labels              = $labelSet.ToArray()
        confidence          = $Confidence
        lang                = "en"
        external_references = @()
        object_marking_refs = @($TLP[$TLPLevel])
        granular_markings   = @()
        extensions          = @{}
    }
}

function ConvertTo-UTCDate([string]$s) {
    $fmts = @("yyyy-MM-dd HH:mm:ss","yyyy-MM-ddTHH:mm:ss","yyyy-MM-ddTHH:mm:ssZ",
              "yyyy-MM-ddTHH:mm:ss.fffZ","MM/dd/yyyy HH:mm:ss","yyyy-MM-dd")
    foreach ($f in $fmts) {
        try {
            return ([DateTime]::ParseExact($s,$f,[System.Globalization.CultureInfo]::InvariantCulture)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        } catch {}
    }
    try { return ([DateTime]::Parse($s)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } catch {}
    return [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

# ─────────────────────────────────────────────────────────────────────────────
#  EXTRACT RAW IOC LIST FROM A FILE
#  Returns: array of @{ Value = "..."; ValidFrom = "..." }
# ─────────────────────────────────────────────────────────────────────────────
function Read-IOCsFromFile([string]$FilePath) {
    $ext  = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $iocs = [System.Collections.Generic.List[hashtable]]::new()

    switch ($ext) {

        { $_ -in '.txt','.list','.dat','.ioc' } {
            # One value per line, skip comments and blanks
            $lines = Get-Content $FilePath -Encoding UTF8 -ErrorAction Stop
            foreach ($line in $lines) {
                $v = $line.Trim()
                if ($v -and $v -notmatch '^(#|//|;)') {
                    $iocs.Add(@{ Value = $v; ValidFrom = "" })
                }
            }
        }

        '.csv' {
            $rows = Import-Csv $FilePath -ErrorAction Stop
            $cols = $rows | Select-Object -First 1 | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            $valCol  = $cols | Where-Object { $_ -match '^(value|indicator|ioc|ip|domain|hash|url)$' } | Select-Object -First 1
            $dateCol = $cols | Where-Object { $_ -match '^(date|update_date|first_seen|timestamp)$' } | Select-Object -First 1
            if (-not $valCol) { $valCol = $cols[0] }   # fallback: first column
            foreach ($row in $rows) {
                $v = $row.$valCol
                if ($v) {
                    $d = if ($dateCol) { $row.$dateCol } else { "" }
                    $iocs.Add(@{ Value = $v.Trim(); ValidFrom = $d })
                }
            }
        }

        '.json' {
            $raw = Get-Content $FilePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            if ($raw -isnot [array]) { $raw = @($raw) }
            foreach ($item in $raw) {
                # Already a STIX indicator — skip (don't re-wrap)
                if ($item.type -eq "indicator" -and $item.pattern) {
                    Write-Log "  [i] Skipping already-STIX object: $($item.id)" -Color DarkGray
                    continue
                }
                # Look for a value field with common names
                $v = $null
                foreach ($f in @('indicator','value','ioc','ip','domain','hash','url','data')) {
                    if ($item.$f) { $v = $item.$f; break }
                }
                if (-not $v) {
                    # Try first string property
                    $item.PSObject.Properties | Where-Object { $_.Value -is [string] } | Select-Object -First 1 | ForEach-Object { $v = $_.Value }
                }
                if ($v) {
                    $d = $item.update_date ?? $item.date ?? $item.first_seen ?? ""
                    $iocs.Add(@{ Value = $v.Trim(); ValidFrom = $d })
                }
            }
        }

        default {
            # Treat unknown extensions as plain text
            $lines = Get-Content $FilePath -Encoding UTF8 -ErrorAction Stop
            foreach ($line in $lines) {
                $v = $line.Trim()
                if ($v -and $v -notmatch '^(#|//|;)') {
                    $iocs.Add(@{ Value = $v; ValidFrom = "" })
                }
            }
        }
    }

    return $iocs.ToArray()
}

# ─────────────────────────────────────────────────────────────────────────────
#  CORE CONVERSION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
function Convert-IOCsToSTIX {
    param(
        [string[]]$FilePaths,
        [string]$OutFolder,
        [bool]$SplitByType,
        [hashtable]$Cfg
    )

    # Result buckets: one list per STIX type
    $buckets = @{}
    foreach ($t in $SUPPORTED_TYPES) { $buckets[$t] = [System.Collections.Generic.List[object]]::new() }

    $seen          = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $totalIn       = 0
    $totalOut      = 0
    $totalDupes    = 0
    $totalUnknown  = 0
    $typeStats     = @{}

    foreach ($file in $FilePaths) {
        Write-Log ""
        Write-Log "  ▶ Reading: $(Split-Path $file -Leaf)" -Color Cyan
        try {
            $rawIocs = Read-IOCsFromFile $file
            Write-Log "    Found $($rawIocs.Count) raw values" -Color DarkGray
            $totalIn += $rawIocs.Count

            foreach ($ioc in $rawIocs) {
                $val = $ioc.Value

                # Deduplicate
                if (-not $seen.Add($val)) { $totalDupes++; continue }

                # Detect type
                $type = Get-IOCType $val
                if (-not $type) {
                    Write-Log "    [?] Unknown type: $val" -Color DarkYellow
                    $totalUnknown++
                    continue
                }

                # Build indicator
                $indicator = New-STIXIndicator `
                    -Type $type -Value $val `
                    -Source $Cfg.Source -ThreatActor $Cfg.ThreatActor `
                    -Tags $Cfg.Tags -Confidence $Cfg.Confidence `
                    -TLPLevel $Cfg.TLPLevel -IndicatorTypes $Cfg.IndicatorTypes `
                    -ValidDays $Cfg.ValidDays -ValidFrom $ioc.ValidFrom

                $buckets[$type].Add($indicator)
                $totalOut++
                if (-not $typeStats.ContainsKey($type)) { $typeStats[$type] = 0 }
                $typeStats[$type]++
            }
        } catch {
            Write-Log "    [ERROR] $($_.Exception.Message)" -Color Red
        }
    }

    # ── Write output ──────────────────────────────────────────────────────────
    # Resolve to absolute path — System.IO.File requires it; relative paths fail
    $OutFolder = [System.IO.Path]::GetFullPath($OutFolder)
    if (-not (Test-Path $OutFolder)) {
        New-Item -ItemType Directory -Path $OutFolder -Force | Out-Null
        Write-Log "  [+] Created folder: $OutFolder" -Color DarkGray
    }

    $writtenFiles = [System.Collections.Generic.List[string]]::new()

    if ($SplitByType) {
        foreach ($type in $typeStats.Keys) {
            $outFile = Join-Path $OutFolder $TYPE_FILENAMES[$type]
            Write-STIXFile -Indicators $buckets[$type].ToArray() -Path $outFile
            $writtenFiles.Add($outFile)
        }
    } else {
        # Merge all into one list
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($t in $SUPPORTED_TYPES) { foreach ($ind in $buckets[$t]) { $all.Add($ind) } }
        $outFile = Join-Path $OutFolder "stix_indicators.json"
        Write-STIXFile -Indicators $all.ToArray() -Path $outFile
        $writtenFiles.Add($outFile)
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    Write-Log ""
    Write-Sep2
    Write-Log "  CONVERSION SUMMARY" -Color Cyan
    Write-Sep2
    Write-Log "  Input values   : $totalIn"    -Color White
    Write-Log "  Generated      : $totalOut"   -Color Green
    Write-Log "  Duplicates     : $totalDupes" -Color DarkGray
    Write-Log "  Unknown/skip   : $totalUnknown" -Color $(if ($totalUnknown) {'Yellow'} else {'DarkGray'})
    Write-Log ""
    Write-Log "  By type:" -Color White
    foreach ($t in $typeStats.Keys | Sort-Object) {
        Write-Log "    $($t.PadRight(25)) $($typeStats[$t])" -Color Cyan
    }
    Write-Log ""
    Write-Log "  Output file(s):" -Color White
    foreach ($f in $writtenFiles) { Write-Log "    → $f" -Color Green }
    Write-Sep2

    return $writtenFiles.ToArray()
}

function Write-STIXFile {
    param([object[]]$Indicators, [string]$Path)

    # Always use absolute path — System.IO.File does not honor PS working directory
    $Path = [System.IO.Path]::GetFullPath($Path)

    Write-Log "  [*] Writing $(if($Indicators){"$($Indicators.Count) indicators"}else{'0 indicators'}) → $Path" -Color Gray

    # Ensure parent folder exists
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    if (-not $Indicators -or $Indicators.Count -eq 0) {
        [System.IO.File]::WriteAllText($Path, "[]", [System.Text.Encoding]::UTF8)
        return
    }

    # ConvertTo-Json with single-element array workaround (PS wraps single objects)
    if ($Indicators.Count -eq 1) {
        $json = "[$($Indicators[0] | ConvertTo-Json -Depth 10)]"
    } else {
        $json = $Indicators | ConvertTo-Json -Depth 10
    }
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)
}

# ─────────────────────────────────────────────────────────────────────────────
#  SENTINEL API UPLOAD (STUB)
#  To enable: set $Cfg.API.Enabled = $true and provide WorkspaceId + BearerToken
# ─────────────────────────────────────────────────────────────────────────────
function Send-ToSentinelAPI {
    param([string[]]$Files, [hashtable]$ApiCfg, [string]$BearerToken)

    if (-not $ApiCfg.Enabled) {
        Write-Log "  [i] API upload is disabled. Enable it in Configuration." -Color Yellow
        return
    }
    if (-not $ApiCfg.WorkspaceId) {
        Write-Log "  [ERROR] WorkspaceId not set in configuration." -Color Red
        return
    }

    $url     = $ApiCfg.Endpoint -replace '\{workspaceId\}', $ApiCfg.WorkspaceId
    $headers = @{ "Authorization" = "Bearer $BearerToken"; "Content-Type" = "application/json" }
    $batch   = [int]$ApiCfg.BatchSize

    foreach ($file in $Files) {
        Write-Log "  [*] Uploading: $(Split-Path $file -Leaf)" -Color Cyan
        $indicators = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($indicators -isnot [array]) { $indicators = @($indicators) }
        $total = $indicators.Count
        $ok    = 0; $fail = 0

        for ($i = 0; $i -lt $total; $i += $batch) {
            $chunk = $indicators[$i..([Math]::Min($i + $batch - 1, $total - 1))]
            $body  = @{ value = $chunk } | ConvertTo-Json -Depth 12 -Compress
            try {
                Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $body -ErrorAction Stop | Out-Null
                $ok += $chunk.Count
                Write-Log "    Batch $([Math]::Floor($i/$batch)+1): $($chunk.Count) OK" -Color Green
            } catch {
                $fail += $chunk.Count
                Write-Log "    Batch $([Math]::Floor($i/$batch)+1) FAILED: $($_.Exception.Message)" -Color Red
            }
        }
        Write-Log "    Total: $ok uploaded, $fail failed" -Color $(if ($fail) {'Yellow'} else {'Green'})
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Show-Banner {
    Clear-Host
    Write-Log "══════════════════════════════════════════════════════" -Color Cyan
    Write-Log "   IOC → STIX 2.1 Converter  |  Microsoft Sentinel    " -Color Cyan
    Write-Log "   v$VERSION  |  Auto-detect · Deduplicate · TLP aware  " -Color DarkCyan
    Write-Log "   Alex Milla · alexmilla.dev                          " -Color DarkGray
    Write-Log "══════════════════════════════════════════════════════" -Color Cyan
    Write-Log ""
}

function Show-Menu {
    Write-Log "  1. " -Color White -NoNewline; Write-Log "Convert file(s)" -Color Green
    Write-Log "  2. " -Color White -NoNewline; Write-Log "Upload to Sentinel API" -Color Cyan
    Write-Log "  3. " -Color White -NoNewline; Write-Log "Configuration" -Color Yellow
    Write-Log "  4. " -Color White -NoNewline; Write-Log "Type detection test (single value)" -Color DarkGray
    Write-Log "  0. " -Color White -NoNewline; Write-Log "Exit" -Color Red
    Write-Log ""
    Write-Sep
}

function Ask {
    param([string]$Prompt, [string]$Default = "")
    if ($Default) {
        $v = Read-Host "$Prompt [$Default]"
        return [string]::IsNullOrWhiteSpace($v) ? $Default : $v
    }
    return Read-Host $Prompt
}

function AskBool([string]$Prompt, [bool]$Default) {
    $def = if ($Default) { "Y" } else { "N" }
    $v   = Ask "$Prompt (Y/N)" -Default $def
    return $v -match '^[Yy]'
}

function Wait-Key {
    Write-Log ""
    Write-Log "  Press any key to continue..." -Color DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Config([hashtable]$Cfg) {
    Write-Log ""
    Write-Log "  Current configuration:" -Color Yellow
    Write-Sep
    $fields = @(
        @{K='OutputFolder';   L='Output folder'},
        @{K='ThreatActor';    L='Threat actor'},
        @{K='Source';         L='Source name'},
        @{K='Tags';           L='Tags'},
        @{K='Confidence';     L='Confidence'},
        @{K='TLPLevel';       L='TLP level'},
        @{K='IndicatorTypes'; L='Indicator type'},
        @{K='ValidDays';      L='Valid days'},
        @{K='LogFile';        L='Log file'}
    )
    foreach ($f in $fields) {
        $val = if ($f.K -eq 'Tags') { if ($Cfg.Tags.Count) { $Cfg.Tags -join ', ' } else { '(none)' } }
               else { if ($Cfg[$f.K]) { $Cfg[$f.K] } else { '(not set)' } }
        Write-Log "  $($f.L.PadRight(20)): $val" -Color White
    }
    Write-Log "  API enabled          : $($Cfg.API.Enabled)" -Color $(if ($Cfg.API.Enabled) {'Green'} else {'DarkGray'})
    if ($Cfg.API.Enabled) {
        Write-Log "  API WorkspaceId      : $($Cfg.API.WorkspaceId)" -Color White
        Write-Log "  API batch size       : $($Cfg.API.BatchSize)" -Color White
    }
    Write-Sep
}

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION MENU
# ─────────────────────────────────────────────────────────────────────────────
function Edit-Config([ref]$CfgRef) {
    $c = $CfgRef.Value
    Show-Config $c
    if (-not (AskBool "  Edit configuration?" $false)) { return }

    Write-Log ""
    # Output folder
    $nf = Ask "  Output folder" -Default $c.OutputFolder
    if ($nf -and -not (Test-Path $nf)) { New-Item -ItemType Directory $nf -Force | Out-Null; Write-Log "  [+] Created: $nf" -Color Green }
    $c.OutputFolder = if ($nf) { $nf } else { $c.OutputFolder }

    # Metadata
    $c.ThreatActor    = Ask "  Threat actor (empty = none)"    -Default $c.ThreatActor
    $c.Source         = Ask "  Source name (e.g. AlienVault)"  -Default $c.Source

    $ti = Ask "  Tags (comma-separated)"  -Default ($c.Tags -join ',')
    $c.Tags = if ($ti) { @($ti -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }

    $c.Confidence     = [int](Ask "  Confidence 1-100"             -Default $c.Confidence)
    $c.TLPLevel       = Ask "  TLP level (white/green/amber/red)" -Default $c.TLPLevel
    $c.IndicatorTypes = Ask "  Indicator type (malicious-activity / anomalous-activity / attribution / compromised / benign / unknown)" -Default $c.IndicatorTypes
    $c.ValidDays      = [int](Ask "  Validity in days"             -Default $c.ValidDays)
    $c.LogFile        = Ask "  Log file path (empty = disabled)"   -Default $c.LogFile

    # API stub config
    Write-Log ""
    Write-Log "  ── API Configuration (Sentinel TI Upload) ──" -Color DarkCyan
    Write-Log "  NOTE: Requires a Bearer token with Sentinel Contributor role." -Color DarkGray
    $c.API.Enabled     = AskBool "  Enable API upload" $c.API.Enabled
    if ($c.API.Enabled) {
        $c.API.WorkspaceId = Ask "  Workspace ID (GUID)" -Default $c.API.WorkspaceId
        $c.API.BatchSize   = [int](Ask "  Batch size" -Default $c.API.BatchSize)
    }

    Save-Config $c
    $CfgRef.Value = $c
    Wait-Key
}

# ─────────────────────────────────────────────────────────────────────────────
#  CONVERT WIZARD
# ─────────────────────────────────────────────────────────────────────────────
function Start-ConvertWizard([hashtable]$Cfg) {
    Write-Log ""
    Write-Log "  ── INPUT ──────────────────────────────────" -Color Cyan
    Write-Log "  Enter a file path or a folder path." -Color DarkGray
    Write-Log "  Supported formats: .txt  .csv  .json  .list  .dat  .ioc" -Color DarkGray
    Write-Log ""

    $inputPath = Ask "  Input path" -Default (Get-Location).Path

    if (-not (Test-Path $inputPath)) {
        Write-Log "  [ERROR] Path not found: $inputPath" -Color Red
        Wait-Key; return
    }

    # Gather files
    $files = @()
    if (Test-Path $inputPath -PathType Container) {
        $files = Get-ChildItem $inputPath -File | Where-Object { $_.Extension -match '^\.(txt|csv|json|list|dat|ioc)$' } | Select-Object -ExpandProperty FullName
        if (-not $files) {
            Write-Log "  [!] No supported files found in folder." -Color Yellow
            Wait-Key; return
        }
        Write-Log "  Found $($files.Count) file(s) in folder:" -Color Green
        foreach ($f in $files) { Write-Log "    · $(Split-Path $f -Leaf)" -Color DarkGray }
    } else {
        $files = @($inputPath)
    }

    Write-Log ""
    Write-Log "  ── OUTPUT ─────────────────────────────────" -Color Cyan
    $outFolder  = Ask "  Output folder" -Default $Cfg.OutputFolder
    $splitFiles = AskBool "  Create separate file per IOC type?" $false

    Write-Log ""
    Write-Log "  ── METADATA (Enter to use config defaults) ─" -Color Cyan
    $source      = Ask "  Source name"         -Default $Cfg.Source
    $actor       = Ask "  Threat actor"        -Default $Cfg.ThreatActor
    $tagsIn      = Ask "  Tags (comma-sep)"    -Default ($Cfg.Tags -join ',')
    $tags        = if ($tagsIn) { @($tagsIn -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @() }
    $confidence  = [int](Ask "  Confidence 1-100"  -Default $Cfg.Confidence)
    $tlp         = Ask "  TLP level"           -Default $Cfg.TLPLevel
    $indType     = Ask "  Indicator type"      -Default $Cfg.IndicatorTypes
    $validDays   = [int](Ask "  Valid days"        -Default $Cfg.ValidDays)

    # Build session config (doesn't overwrite saved config)
    $sessionCfg = $Cfg.Clone()
    $sessionCfg.Source         = $source
    $sessionCfg.ThreatActor    = $actor
    $sessionCfg.Tags           = $tags
    $sessionCfg.Confidence     = $confidence
    $sessionCfg.TLPLevel       = $tlp
    $sessionCfg.IndicatorTypes = $indType
    $sessionCfg.ValidDays      = $validDays

    Write-Log ""
    Write-Sep2
    Write-Log "  CONVERTING..." -Color Yellow
    Write-Sep2

    $outFiles = Convert-IOCsToSTIX -FilePaths $files -OutFolder $outFolder -SplitByType $splitFiles -Cfg $sessionCfg

    # Offer API upload if enabled
    if ($Cfg.API.Enabled -and $outFiles.Count -gt 0) {
        Write-Log ""
        if (AskBool "  Upload to Sentinel API now?" $false) {
            $token = Read-Host "  Bearer Token" -AsSecureString
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                         [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token))
            Send-ToSentinelAPI -Files $outFiles -ApiCfg $Cfg.API -BearerToken $plain
        }
    }

    Wait-Key
}

# ─────────────────────────────────────────────────────────────────────────────
#  API UPLOAD MENU
# ─────────────────────────────────────────────────────────────────────────────
function Start-APIUpload([hashtable]$Cfg, [ref]$CfgRef) {
    Write-Log ""
    Write-Log "  ── SENTINEL API UPLOAD ────────────────────" -Color Cyan

    # If not configured, offer to configure inline without leaving the menu
    if (-not $Cfg.API.Enabled -or -not $Cfg.API.WorkspaceId) {
        Write-Log ""
        if ($Cfg.API.Enabled) {
            Write-Log "  [!] API is enabled but WorkspaceId is missing." -Color Yellow
        } else {
            Write-Log "  [!] API upload is not configured yet." -Color Yellow
        }
        Write-Log ""
        if (-not (AskBool "  Configure API now?" $true)) { Wait-Key; return }

        Write-Log ""
        Write-Log "  NOTE: Requires a Bearer token with Sentinel Contributor role." -Color DarkGray
        $Cfg.API.Enabled     = $true
        $Cfg.API.WorkspaceId = Ask "  Workspace ID (GUID)" -Default $Cfg.API.WorkspaceId
        $batchInput          = Ask "  Batch size"          -Default $Cfg.API.BatchSize
        $Cfg.API.BatchSize   = [int]$batchInput

        Save-Config $Cfg
        $CfgRef.Value = $Cfg
        Write-Log "  [OK] API configuration saved." -Color Green
        Write-Log ""
    }

    # Show current API config before proceeding
    Write-Log "  Workspace ID  : $($Cfg.API.WorkspaceId)" -Color DarkGray
    Write-Log "  Batch size    : $($Cfg.API.BatchSize)"   -Color DarkGray
    Write-Log ""

    $defaultFile = Join-Path $Cfg.OutputFolder "stix_indicators.json"
    $file = Ask "  STIX JSON file to upload" -Default $defaultFile
    $file = [System.IO.Path]::GetFullPath($file)

    if (-not (Test-Path $file)) {
        Write-Log "  [ERROR] File not found: $file" -Color Red
        Wait-Key; return
    }

    Write-Log ""
    $token = Read-Host "  Bearer Token" -AsSecureString
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                 [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token))
    Send-ToSentinelAPI -Files @($file) -ApiCfg $Cfg.API -BearerToken $plain
    Wait-Key
}

# ─────────────────────────────────────────────────────────────────────────────
#  TYPE DETECTION TEST
# ─────────────────────────────────────────────────────────────────────────────
function Start-DetectionTest {
    Write-Log ""
    Write-Log "  Enter a value to test auto-detection (empty to exit):" -Color DarkGray
    while ($true) {
        $v = Read-Host "  Value"
        if ([string]::IsNullOrWhiteSpace($v)) { break }
        $t = Get-IOCType $v
        if ($t) {
            Write-Log "  → Detected: " -Color White -NoNewline
            Write-Log $t -Color Green -NoNewline
            $p = New-STIXPattern -Type $t -Value $v
            Write-Log "   Pattern: $p" -Color DarkCyan
        } else {
            Write-Log "  → Unknown / unsupported type" -Color Yellow
        }
    }
    Wait-Key
}

# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────
function Start-Interactive {
    $cfg     = Load-Config
    $running = $true

    # Apply log file from config
    if ($cfg.LogFile) { $script:_logFile = $cfg.LogFile }

    while ($running) {
        Show-Banner
        Show-Menu
        $choice = Read-Host "  Option"

        switch ($choice.Trim()) {
            '1' { Show-Banner; Start-ConvertWizard $cfg }
            '2' { Show-Banner; Start-APIUpload $cfg ([ref]$cfg) }
            '3' { Show-Banner; Edit-Config ([ref]$cfg); if ($cfg.LogFile) { $script:_logFile = $cfg.LogFile } }
            '4' { Show-Banner; Start-DetectionTest }
            '0' { $running = $false }
            default { Write-Log "  [!] Invalid option." -Color Red; Start-Sleep 1 }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if ($NonInteractive -and $InputPath) {
    # Pipeline mode
    $cfg = Load-Config
    if ($LogFile)    { $script:_logFile = $LogFile }
    if ($OutputPath) { $cfg.OutputFolder = $OutputPath }
    $files = @()
    if (Test-Path $InputPath -PathType Container) {
        $files = Get-ChildItem $InputPath -File | Where-Object { $_.Extension -match '^\.(txt|csv|json|list|dat|ioc)$' } | Select-Object -ExpandProperty FullName
    } else {
        $files = @($InputPath)
    }
    Convert-IOCsToSTIX -FilePaths $files -OutFolder $cfg.OutputFolder -SplitByType $SplitByType -Cfg $cfg
} else {
    Start-Interactive
}
