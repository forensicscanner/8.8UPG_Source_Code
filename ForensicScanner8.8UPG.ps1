# ForensicScanner 8.8 - Roblox-focused Windows forensic detection pipeline
# Created by Mito | presentation, Defender-resource, and scan-completeness fixes
# 8.8: fixes RawEvidence/Evidence sync in correlation and final confidence scoring.
# Performance: first baseline keeps full SHA256 coverage but defers PE/signature work
# for ordinary binaries; suspicious binaries and later changed binaries retain deep checks.
# 8.7: previous event-log counting bug fixed; additional correlation issue identified and corrected.
# 8.6: fixes self-folder path boundaries and prevents incomplete/errored enumeration from updating baseline.
# 8.2: separates weak static binary strings from actual behavior indicators to
# reduce false positives; binary strings remain supporting evidence only.
# Detection is evidence-based: unsigned status, path risk, or a single API string is not proof.

[CmdletBinding()]
param(
  [switch]$Monitor,
  [ValidateRange(2,300)]
  [int]$MonitorIntervalSeconds = 8
)

# Startup attribution banner (kept after param so PowerShell parameter binding works).
# Keep the banner visible for 3 seconds; do not clear it later during initialization.
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '                 FORENSIC SCANNER 8.8' -ForegroundColor White
Write-Host '                      MADE BY MITO' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Start-Sleep -Seconds 3

$ErrorActionPreference = 'SilentlyContinue'  # Keep console quiet; individual operations use explicit try/catch and scanStats counters.

$ProgressPreference = 'SilentlyContinue'

$scriptVersion = '8.8'

$minimumPowerShellMajor = 5

$scriptStart = Get-Date

# Single performance profile: balanced, without sacrificing detection coverage.
# These values only control pacing/priority; no detection module is disabled.

$scanDeadline = $scriptStart.AddMinutes(30)

$monitorIntervalSeconds = $MonitorIntervalSeconds

$monitorModuleIntervalSeconds = 15

$fileThrottleMilliseconds = 3

$fileBurstSize = 60

$scannerPriority = 'BelowNormal'

$monitorProcessBaselineReady = $false

$monitorModuleBaselineReady = $false

$monitorIdentityCache = @{}

$monitorIdentityCacheTtlSeconds = 300

$scannerDataRoot = Join-Path $env:ProgramData 'ForensicScanner'
try {
  if (-not (Test-Path -LiteralPath $scannerDataRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $scannerDataRoot -Force -ErrorAction Stop | Out-Null
  }
  $writeProbe = Join-Path $scannerDataRoot ('.write-test-' + [guid]::NewGuid().ToString('N'))
  [System.IO.File]::WriteAllText($writeProbe, 'test')
  [System.IO.File]::Delete($writeProbe)
} catch {
  $scannerDataRoot = Join-Path $env:LOCALAPPDATA 'ForensicScanner'
  try {
    if (-not (Test-Path -LiteralPath $scannerDataRoot -PathType Container)) {
      New-Item -ItemType Directory -Path $scannerDataRoot -Force -ErrorAction Stop | Out-Null
    }
  } catch {
    Write-Warning 'Neither ProgramData nor LocalAppData is writable; reports and baseline may not be saved.'
  }
}

$monitorStatePath = Join-Path $scannerDataRoot 'monitor-state.json'

$hashListDirectory = $scannerDataRoot

$highKeywords = @('synapse','krnl','fluxus','jjsploit','vegax','solara','xeno','arceus','hydrogen','ronix','bytebreaker','scriptware','matcha') | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique

$mediumKeywords = @('newgui','executor','injector','exploit','dllinject','infyield') | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique

$genericKeywords = @('updater','electron','hook','wave','swift','delta','velocity') | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique

$behaviorKeywords = @('loadlibrary','virtualalloc','virtualprotect','writeprocessmemory','createremotethread','ntwritevirtualmemory','setwindowshook','openprocess','mapviewofsection','queueuserapc','createprocess','powershell','pwsh','mshta','rundll32','regsvr32','wscript','cscript','encodedcommand','frombase64string','invoke-expression','add-type','assembly]::load','downloadstring','downloadfile','webclient','httpclient','getgenv','getrenv','getfenv','hookfunction','hookmetamethod','getrawmetatable','setreadonly','make_writeable','identifyexecutor','queue_on_teleport','firetouchinterest','getconnections','getgc','getinstances','getscripts','getloadedmodules','drawing.new','syn.request','http_request') | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique

$genericContextRegex = [regex]::new('(?i)(roblox|executor|exploit|inject(?:or)?|loadlibrary|virtualalloc|virtualprotect|writeprocessmemory|createremotethread|setwindowshook|powershell|mshta|rundll32|regsvr32|encodedcommand|downloadstring|frombase64string)',[System.Text.RegularExpressions.RegexOptions]'Compiled')

$trustedPublishers = @('Microsoft Corporation','Microsoft Windows','Roblox Corporation')

$highRiskExtensions = @('.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs','.js','.lnk','.lua','.luau')

$robloxProcessNames = @('RobloxPlayerBeta.exe','RobloxStudioBeta.exe')

$robloxInstallPattern = '(?i)\\Roblox\\Versions\\'

$excludedPathPattern = '(?i)\\(node_modules|WindowsApps|Packages\\Microsoft\.|Google\\Chrome\\User Data\\.*\\Cache|Microsoft\\Edge\\User Data\\.*\\Cache|Mozilla\\Firefox\\Profiles\\.*\\cache2|Steam\\steamapps|\.git|__pycache__)\\'

$selfPath = $MyInvocation.MyCommand.Path

$selfDir = if ($selfPath) { Split-Path $selfPath -Parent } else { '' }

$knownCheatHashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$knownGoodHashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$monitorSeenProcesses = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$monitorSeenFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$monitorSeenModules = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$monitorWatchers = [System.Collections.Generic.List[object]]::new()

$monitorEvents = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()

$monitorStarted = $false

$monitorMaxEventsPerCycle = 32
$monitorMaxFileFindingsPerCycle = 16
$monitorConsoleIntervalSeconds = 5

$hashCache = @{}

$baselinePath = Join-Path $scannerDataRoot 'file-baseline.json'

$baselineEntries = @{}

$baselineInitialized = $false

$baselineLoadFailed = $false

$baselineUpdated = $false

$results = [System.Collections.Generic.List[object]]::new()

$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$resultIndex = @{}

$scanStartedUtc = (Get-Date).ToUniversalTime()

$reportDirectory = Join-Path $scannerDataRoot 'Reports'

$allowlistPath = Join-Path $scannerDataRoot 'allowlist.txt'

$script:allowlistEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$counts = @{Registry=0;Startup=0;Files=0;Processes=0;Tasks=0;Services=0;Prefetch=0;DNS=0;Profiles=0;Defender=0;EventLogs=0;RunMRU=0;RobloxModules=0;Artifacts=0;Integrity=0;Historical=0;RecycleBin=0;Cache=0}

$scanStats = @{FileErrors=0;EnumerationErrors=0;WatcherErrors=0;ProcessErrors=0;EventsChecked=0;ScanTimedOut=0}

$maxStoredFindings = 2000
$maxWorkerFindings = 2000
$maxUserAssistKeys = 5000
$maxPrefetchItems = 5000
$maxRegistryKeys = 5000

$maxConsoleFindings = 12

$maxReportListFindings = 75

$maxEvidenceChars = 450

$script:suppressedFindings = 0

function Load-Allowlist {

  try {

      if(-not(Test-Path -LiteralPath $allowlistPath -PathType Leaf)){return}

      foreach($line in @(Get-Content -LiteralPath $allowlistPath -ErrorAction SilentlyContinue)){

          $v=([string]$line).Trim()

          if($v -and -not $v.StartsWith('#')){[void]$script:allowlistEntries.Add($v)}

      }

  }catch{}

}

function Test-Allowlisted {

  param([string]$Path,[string]$Hash='', [string]$Publisher='')

  if($Hash -and $script:allowlistEntries.Contains($Hash)){return $true}

  if($Path -and $script:allowlistEntries.Contains($Path)){return $true}

  # Publisher strings in PE version resources are self-asserted metadata, not signer identity.
  # They must never suppress a finding by themselves. Use exact SHA256 or exact path entries.

  return $false

}

function Get-DisplayFindingPath {
  param([string]$Path,[int]$MaxChars=170)

  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }

  # Defender Resources may contain several typed resources, including a full
  # web URL with query/response metadata. Keep the local file path for display.
  $raw = ([string]$Path -replace '[\x00-\x1F]', ' ').Trim()
  # Defender may separate resource entries with whitespace, pipes or semicolons.
  $parts = @([regex]::Split($raw, '(?i)(?:\s+|\|+|;)(?=(?:file|webfile|containerfile):)') | Where-Object { $_ -and $_.Trim() })
  $display = [System.Collections.Generic.List[string]]::new()

  foreach ($part in $parts) {
    $value = ([string]$part).Trim().Trim('"')
    if ($value -match '(?i)^webfile:\s*_?([^|]+)') {
      $value = $matches[1].Trim()
    } elseif ($value -match '(?i)^file:\s*_?(.+)$') {
      $value = $matches[1].Trim()
    } elseif ($value -match '(?i)^containerfile:\s*_?([^|]+)') {
      $value = $matches[1].Trim()
    }

    # If a resource is only a URL, show its host instead of a long signed URL.
    if ($value -match '^https?://') {
      try { $uri = [uri]$value; $value = "Web resource: $($uri.Host)" } catch { $value = 'Web resource' }
    }

    $value = $value -replace '\s+', ' '
    $value = $value.Trim()
    if ($value -and -not $display.Contains($value)) { [void]$display.Add($value) }
  }

  if ($display.Count -eq 0) { $displayText = $raw } else { $displayText = $display[0] }
  if ($display.Count -gt 1) { $displayText += " (+$($display.Count - 1) more resources)" }

  if ($displayText.Length -gt $MaxChars) {
    $keep = [Math]::Max(24, $MaxChars - 3)
    $displayText = $displayText.Substring(0, $keep) + '...'
  }
  return $displayText
}

function Get-ConciseEvidence {
  param([string]$Evidence,[int]$MaxChars=450)

  if ([string]::IsNullOrWhiteSpace($Evidence)) { return '' }

  $text = [string]$Evidence
  $text = $text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' '
  $text = $text -replace '\s+', ' '
  $text = $text.Trim()

  # Prefer the first few meaningful evidence clauses rather than dumping raw event text.
  $parts = @($text -split '\s*;\s*' | Where-Object { $_ -and $_.Trim() })
  if ($parts.Count -gt 3) { $parts = @($parts | Select-Object -First 3) }
  $out = ($parts -join '; ')

  if ($out.Length -gt $MaxChars) {
      $out = $out.Substring(0,[Math]::Max(0,$MaxChars-3)) + '...'
  }

  return $out
}

function Add-TextEvidence {
  param(
    [object]$Target,
    [string]$AddedEvidence
  )

  if ($null -eq $Target -or [string]::IsNullOrWhiteSpace($AddedEvidence)) { return }

  $cleanAdded = ([string]$AddedEvidence -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' ').Trim()
  if ([string]::IsNullOrWhiteSpace($cleanAdded)) { return }

  # Merge individual evidence fragments rather than comparing one joined string.
  # This prevents repeated fragments when several independent sources update one finding.
  $rawParts = [System.Collections.Generic.List[string]]::new()
  $rawSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  $existingRaw = if ($Target.PSObject.Properties['RawEvidence']) { [string]$Target.RawEvidence } else { '' }
  $combinedRaw = @($existingRaw, $cleanAdded) -join '; '
  foreach ($part in ($combinedRaw -split '\s*;\s*')) {
    $fragment = ([string]$part).Trim()
    if ($fragment -and $rawSeen.Add($fragment)) { [void]$rawParts.Add($fragment) }
  }

  $mergedRaw = $rawParts -join '; '
  if ($mergedRaw.Length -gt 4500) { $mergedRaw = $mergedRaw.Substring(0, 4497) + '...' }
  $Target.RawEvidence = $mergedRaw

  $existingSafe = if ($Target.PSObject.Properties['Evidence']) { [string]$Target.Evidence } else { '' }
  $addedSafe = Get-ConciseEvidence $cleanAdded $maxEvidenceChars
  if ($addedSafe) {
    $safeParts = [System.Collections.Generic.List[string]]::new()
    $safeSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $combinedSafe = @($existingSafe, $addedSafe) -join '; '
    foreach ($part in ($combinedSafe -split '\s*;\s*')) {
      $fragment = ([string]$part).Trim()
      if ($fragment -and $safeSeen.Add($fragment)) { [void]$safeParts.Add($fragment) }
    }

    $mergedSafe = $safeParts -join '; '
    if ($mergedSafe.Length -gt 1800) { $mergedSafe = $mergedSafe.Substring(0, 1797) + '...' }
    $Target.Evidence = $mergedSafe
  }
}

function Add-Result {

  param([string]$Type,[string]$Name,[string]$Path,[string]$Details='',[string]$Severity='INFO',[int]$Score=0,[string]$Confidence='Low',[string]$Keyword='',[string]$Evidence='')

  # Keep the in-memory result set bounded. If full, retain only stronger findings.

  # Live Defender history and historical Defender artifacts can describe the
  # same detection. Normalize their type and resource path for deduplication,
  # while preserving the original Type and Path on the stored finding.
  $dedupType = $Type
  $dedupPath = $Path
  if ($Type -in @('Defender Detection','Historical Defender Artifact')) {
      $dedupType = 'Defender Detection'
      $dedupPath = Get-DisplayFindingPath ([string]$Path) 1000
  }
  $key="$dedupType|$Name|$dedupPath"

  if($seen.Contains($key)){

      $existing=$script:resultIndex[$key]

      if($existing){

          $existing.Score=[Math]::Max([int]$existing.Score,[int]$Score)

          $existing.Severity=Get-SeverityFromScore $existing.Score

          if($Evidence){
              Add-TextEvidence -Target $existing -AddedEvidence $Evidence
          }

          if($Keyword -and $existing.Keyword -notmatch [regex]::Escape($Keyword)){
              $existing.Keyword=($existing.Keyword+', '+$Keyword).Trim(', ')
          }

          if($existing.Sources -notcontains $Type){$existing.Sources=@($existing.Sources)+$Type}

      }

      return

  }

  if($script:results.Count -ge $maxStoredFindings){

      $weakest=$script:results | Sort-Object Score | Select-Object -First 1

      if(-not $weakest -or [int]$Score -le [int]$weakest.Score){

          $script:suppressedFindings++

          return

      }

      $weakDedupType = [string]$weakest.Type
      $weakDedupPath = [string]$weakest.Path
      if ($weakest.Type -in @('Defender Detection','Historical Defender Artifact')) {
          $weakDedupType = 'Defender Detection'
          $weakDedupPath = Get-DisplayFindingPath ([string]$weakest.Path) 1000
      }
      $weakKey="$weakDedupType|$($weakest.Name)|$weakDedupPath"

      [void]$script:seen.Remove($weakKey)

      [void]$script:resultIndex.Remove($weakKey)

      [void]$script:results.Remove($weakest)

      $script:suppressedFindings++

  }

  $safeEvidence=Get-ConciseEvidence $Evidence $maxEvidenceChars
  $rawEvidence=[string]$Evidence
  $rawEvidence=$rawEvidence -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]',' '
  if($rawEvidence.Length -gt 4500){$rawEvidence=$rawEvidence.Substring(0,4497)+'...'}

  $obj=[PSCustomObject]@{

      Type=$Type;Name=$Name;Path=$Path;Details=$Details

      Severity=$Severity;Score=$Score;Confidence=$Confidence

      Keyword=$Keyword;Evidence=$safeEvidence;RawEvidence=$rawEvidence

      FirstSeen=(Get-Date).ToString('o');Sources=@($Type)

  }

  [void]$results.Add($obj)

  # Keep the deduplication set in sync with the result list/index.

  [void]$script:seen.Add($key)

  $script:resultIndex[$key]=$obj

}

function Test-ScannerEnvironment {

  if ($PSVersionTable.PSVersion.Major -lt $minimumPowerShellMajor) {

      Write-Host "[-] PowerShell $minimumPowerShellMajor or newer is required. Detected: $($PSVersionTable.PSVersion)" -ForegroundColor Red

      return $false

  }

  if ($env:OS -ne 'Windows_NT') {

      Write-Host '[-] This scanner requires Windows.' -ForegroundColor Red

      return $false

  }

  return $true

}

function Initialize-Indicators {

  foreach ($x in @()) { if ($x) { [void]$script:knownCheatHashes.Add(([string]$x).ToUpperInvariant()) } }

  foreach ($x in @()) { if ($x) { [void]$script:knownGoodHashes.Add(([string]$x).ToUpperInvariant()) } }

}

Initialize-Indicators

function Load-ExternalHashLists {

  $files=@(

      (Join-Path $hashListDirectory 'known-cheat-hashes.txt'),

      (Join-Path $hashListDirectory 'known-good-hashes.txt'),

      (if($selfDir){Join-Path $selfDir 'known-cheat-hashes.txt'}else{''}),

      (if($selfDir){Join-Path $selfDir 'known-good-hashes.txt'}else{''})

  ) | Where-Object { $_ } | Select-Object -Unique

  foreach($file in $files){

      try{

          if(-not(Test-Path -LiteralPath $file -PathType Leaf)){continue}

          foreach($line in @(Get-Content -LiteralPath $file -ErrorAction SilentlyContinue)){

              $h=([string]$line).Trim().ToUpperInvariant()

              if($h -match '^[A-F0-9]{64}$'){

                  if($file -match '(?i)known-cheat-hashes') {[void]$script:knownCheatHashes.Add($h)}

                  elseif($file -match '(?i)known-good-hashes') {[void]$script:knownGoodHashes.Add($h)}

              }

          }

      }catch{}

  }

}

Load-ExternalHashLists

Load-Allowlist

$highRegex = [regex]::new('(?<![A-Za-z0-9])(?:'+(($highKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|')+')(?![A-Za-z0-9])', [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

$mediumRegex = [regex]::new('(?<![A-Za-z0-9])(?:'+(($mediumKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|')+')(?![A-Za-z0-9])', [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

$genericRegex = [regex]::new('(?<![A-Za-z0-9])(?:'+(($genericKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|')+')(?![A-Za-z0-9])', [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

$behaviorRegex = [regex]::new(($behaviorKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|', [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

function Get-MatchedKeywords {

  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

  $out = [System.Collections.Generic.List[string]]::new()

  foreach ($regex in @($highRegex,$mediumRegex)) {

      foreach ($m in $regex.Matches($Text)) { [void]$out.Add($m.Value.ToLowerInvariant()) }

  }

  # Generic indicators are intentionally context-gated to reduce false positives.

  if ($genericRegex.IsMatch($Text) -and $genericContextRegex.IsMatch($Text)) {

      foreach ($m in $genericRegex.Matches($Text)) { [void]$out.Add($m.Value.ToLowerInvariant()) }

  }

  return @($out | Select-Object -Unique)

}

function Get-MatchedBehavior {

  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

  $out = [System.Collections.Generic.List[string]]::new()

  foreach ($m in $behaviorRegex.Matches($Text)) { [void]$out.Add($m.Value.ToLowerInvariant()) }

  return @($out | Select-Object -Unique)

}

function Get-KeywordTier {

  param([string[]]$Matched)

  if (-not $Matched -or $Matched.Count -eq 0) { return 'None' }

  foreach ($x in $Matched) { if ($highKeywords -contains $x) { return 'High' } }

  foreach ($x in $Matched) { if ($mediumKeywords -contains $x) { return 'Medium' } }

  return 'Generic'

}

function Test-PathExcluded {

  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

  if ($Path -match $excludedPathPattern) { return $true }

  if ($selfDir) {

      try {
          $normalizedSelf = [System.IO.Path]::GetFullPath($selfDir).TrimEnd('\')
          $normalizedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')

          # Require a directory boundary: C:\Tools must not also match C:\Tools2.
          if ([string]::Equals($normalizedPath,$normalizedSelf,[System.StringComparison]::OrdinalIgnoreCase) -or
              $normalizedPath.StartsWith(($normalizedSelf + '\'),[System.StringComparison]::OrdinalIgnoreCase)) {
              return $true
          }
      } catch {}

  }

  return $false

}

function Test-MeaningfulSuspicionContext {
  param(
      [string]$Name='',
      [string]$Path='',
      [string]$CommandLine='',
      [string]$ExtraText='',
      [string]$Publisher='',
      [string]$OriginalFilename='',
      [int]$ExecutionBonus=0,
      [int]$InjectionBonus=0
  )

  $combined="$Name $Path $CommandLine $ExtraText $Publisher $OriginalFilename"

  $behavior=@(Get-MatchedBehavior $combined)
  $robloxContext=$combined -match '(?i)(robloxplayerbeta|robloxstudiobeta|\\Roblox\\Versions\\|roblox)'
  $explicitSuspicion=$combined -match '(?i)(executor|exploit|inject(?:or)?|loadlibrary|virtualalloc|virtualprotect|writeprocessmemory|createremotethread|setwindowshook|encodedcommand|downloadstring|frombase64string|rundll32|regsvr32|mshta)'

  return ($behavior.Count -gt 0 -or $robloxContext -or $explicitSuspicion -or $ExecutionBonus -gt 0 -or $InjectionBonus -gt 0)
}

function Get-PathRisk {

  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return 0 }

  if ($Path -match '(?i)\\(Downloads|Desktop|Temp|ProgramData|Windows\\Temp)\\' -or $Path -match '(?i)\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\') { return 2 }

  return 0

}

function Get-FileHashSafe {

  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }

  try {

      $item = Get-Item -LiteralPath $Path -ErrorAction Stop

      if (-not $item.PSIsContainer) {

          # Include size + mtime in the cache key so a modified file never reuses an old hash.

          $key = "$($item.FullName)|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"

          if ($hashCache.ContainsKey($key)) { return [string]$hashCache[$key] }

          $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()

          $hashCache[$key] = $hash

          if ($hashCache.Count -gt 2048) {

              foreach ($k in @($hashCache.Keys)) {

                  if ($k -notlike "$($item.FullName)|*") {

                      [void]$hashCache.Remove($k)

                      if ($hashCache.Count -le 1536) { break }

                  }

              }

          }

          return $hash

      }

  } catch {

      $script:scanStats.FileErrors++

  }

  return ''

}

function Get-FileSignatureStatus {

  param([string]$Path)

  try {

      if (Test-Path -LiteralPath $Path -PathType Leaf) { return [string](Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status }

  } catch {}

  return ''

}

function Get-FileSignerSubject {

  param([string]$Path)

  try {
      if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return ''}
      $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
      if($signature.Status -eq 'Valid' -and $signature.SignerCertificate){return [string]$signature.SignerCertificate.Subject}
  } catch {}
  return ''

}

function Get-PEMetadata {

  param([string]$Path)

  try {

      if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

      $item = Get-Item -LiteralPath $Path -ErrorAction Stop

      if ($item.Extension -notmatch '(?i)^\.(exe|dll|sys)$') { return $null }

      $v = $item.VersionInfo

      [PSCustomObject]@{

          Company=[string]$v.CompanyName

          Product=[string]$v.ProductName

          Description=[string]$v.FileDescription

          OriginalFilename=[string]$v.OriginalFilename

          ProductVersion=[string]$v.ProductVersion

          FileVersion=[string]$v.FileVersion

      }

  } catch { return $null }

}

function Get-BinaryStringIndicators {

  param([string]$Path,[int64]$MaxBytes=4194304)

  # Sample bounded windows across the file. Static strings are weak triage evidence,
  # not proof that a binary executes or calls the referenced APIs.
  try {
      if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
      $fs=[System.IO.File]::Open($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
      try {
          $length=[int64]$fs.Length
          if($length -le 0){return @()}
          if($length -le $MaxBytes){$windowSize=[int]$length;$offsets=@([int64]0)}
          else {
              $windowSize=[int][Math]::Max(1,[Math]::Floor($MaxBytes/5))
              $last=[int64]($length-$windowSize)
              $offsets=@([int64]0,[int64][Math]::Max(0,[Math]::Floor($last*0.25)),[int64][Math]::Max(0,[Math]::Floor($last*0.50)),[int64][Math]::Max(0,[Math]::Floor($last*0.75)),$last) | Select-Object -Unique
          }
          $builder=[System.Text.StringBuilder]::new()
          foreach($offset in $offsets){
              [void]$fs.Seek([int64]$offset,[System.IO.SeekOrigin]::Begin)
              $count=[int][Math]::Min($windowSize,$length-$offset)
              if($count -le 0){continue}
              $buffer=New-Object byte[] $count
              $read=0
              while($read -lt $count){$chunk=$fs.Read($buffer,$read,$count-$read);if($chunk -le 0){break};$read+=$chunk}
              if($read -gt 0){[void]$builder.Append([System.Text.Encoding]::ASCII.GetString($buffer,0,$read));[void]$builder.Append(' ');[void]$builder.Append([System.Text.Encoding]::Unicode.GetString($buffer,0,$read))}
          }
          $found=@(Get-MatchedBehavior $builder.ToString() | Where-Object {$_ -in @('loadlibrary','writeprocessmemory','createremotethread','ntwritevirtualmemory','mapviewofsection','queueuserapc','setwindowshook','openprocess','virtualalloc','virtualprotect')} | Select-Object -Unique)
          return $found
      } finally { $fs.Dispose() }
  } catch { return @() }
}

function Get-FileIdentity {

  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  try {

      if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

      $item = Get-Item -LiteralPath $Path -ErrorAction Stop

      $ext = $item.Extension.ToLowerInvariant()

      if ($ext -notin @('.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs','.js','.lnk','.lua','.luau')) { return $null }

      $hash = ''

      if ($ext -in @('.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs','.js','.lnk','.lua','.luau')) { $hash = Get-FileHashSafe $Path }

      $meta = Get-PEMetadata $Path

      $sig = if ($ext -in @('.exe','.dll','.sys')) { Get-FileSignatureStatus $Path } else { '' }

      [PSCustomObject]@{

          Path=$item.FullName

          Name=$item.Name

          Extension=$ext

          Length=[int64]$item.Length

          CreationTimeUtc=$item.CreationTimeUtc.ToString('o')

          LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')

          SHA256=$hash

          Company=if($meta){$meta.Company}else{''}

          Product=if($meta){$meta.Product}else{''}

          Description=if($meta){$meta.Description}else{''}

          OriginalFilename=if($meta){$meta.OriginalFilename}else{''}

          ProductVersion=if($meta){$meta.ProductVersion}else{''}

          FileVersion=if($meta){$meta.FileVersion}else{''}

          Signature=$sig

          Publisher=if($meta){$meta.Company}else{''}

      }

  } catch { return $null }

}

function Get-SuspicionScore {

  param([string]$Name='', [string]$Path='', [string]$CommandLine='', [string]$Hash='', [string]$Signature='', [string]$ExtraText='', [int]$ExecutionBonus=0, [int]$InjectionBonus=0, [string]$Publisher='', [string]$OriginalFilename='', [int]$AgeDays=-1)

  $score=0

  $combined="$Name $Path $CommandLine $ExtraText $Publisher $OriginalFilename"

  $matched=@(Get-MatchedKeywords $combined)

  $behavior=@(Get-MatchedBehavior $combined)
  $isBinary=$Path -match '(?i)\.(exe|dll|sys)$'
  $validSignature=$isBinary -and $Signature -eq 'Valid'

  $publisherTrusted=$false
  # Trust the actual Authenticode signer subject, never the editable PE CompanyName field.
  $signerSubject=if($validSignature){Get-FileSignerSubject $Path}else{''}
  foreach($tp in $trustedPublishers){if($signerSubject -and $signerSubject -match [regex]::Escape($tp)){$publisherTrusted=$true;break}}

  $robloxContext=$combined -match '(?i)(robloxplayerbeta|robloxstudiobeta|\\Roblox\\Versions\\|roblox)'

  $memoryBehavior=@('loadlibrary','writeprocessmemory','createremotethread','ntwritevirtualmemory','mapviewofsection','queueuserapc','setwindowshook','openprocess','virtualalloc','virtualprotect')

  $strongBehaviorCount=@($behavior|Where-Object{$_ -in $memoryBehavior}).Count

  if($Hash -and $knownCheatHashes.Contains($Hash)){$score+=15}

  if($Hash -and $knownGoodHashes.Contains($Hash)){$score=[Math]::Max(0,$score-10)}

  # Location and signature state are supporting evidence, not detections by themselves.
  # A writable path or an unsigned binary is common on normal Windows software.
  if($validSignature -and $publisherTrusted){$score=[Math]::Max(0,$score-2)}

  if($strongBehaviorCount -ge 2){$score+=3}elseif($strongBehaviorCount -eq 1){$score+=1}

  if($behavior.Count -ge 3 -and $strongBehaviorCount -ge 1){$score+=1}

  if($robloxContext -and $behavior.Count -ge 1){$score+=2}

  $meaningfulContextForPath=($behavior.Count -gt 0 -or $robloxContext -or $ExecutionBonus -gt 0 -or $InjectionBonus -gt 0)
  if($meaningfulContextForPath -and $isBinary -and $Signature -eq 'NotSigned'){$score+=1}
  if($meaningfulContextForPath -and (Get-PathRisk $Path) -gt 0){$score+=1}

  if($OriginalFilename -and $Name -and ([System.IO.Path]::GetFileName($OriginalFilename) -ne $Name) -and $Name -notmatch '(?i)^Roblox'){$score+=1}

  if($matched.Count){
      $tier=Get-KeywordTier $matched
      $meaningfulContext = ($behavior.Count -gt 0 -or $robloxContext -or $ExecutionBonus -gt 0 -or $InjectionBonus -gt 0)

      # Names such as updater/electron/delta/etc. are never a score by themselves.
      # Even cheat-family keywords are supporting evidence unless paired with context.
      if($meaningfulContext){
          if($tier -eq 'High'){$score+=2}
          elseif($tier -eq 'Medium'){$score+=1}
      }
  }

  $score += [Math]::Min(3,[Math]::Max(0,$ExecutionBonus))

  $score += [Math]::Min(4,[Math]::Max(0,$InjectionBonus))

  if(Test-Allowlisted -Path $Path -Hash $Hash -Publisher $Publisher){$score=[Math]::Max(0,$score-8)}

  return [Math]::Min(25,[Math]::Max(0,$score))

}

function Get-SeverityFromScore {

  param([int]$Score)

  if($Score -ge 14){return 'HIGH'}

  if($Score -ge 8){return 'MEDIUM'}

  if($Score -ge 4){return 'LOW'}

  return 'INFO'

}

function Get-Confidence {

  param([int]$Score,[string]$Evidence)

  # Strip weak static-string notes before confidence scoring so an API name embedded
  # in a binary cannot masquerade as observed behavior.
  $confidenceEvidence=[regex]::Replace($Evidence,'(?i)Binary API strings \(weak static evidence; not proof of execution\):[^;]*','')

  if($confidenceEvidence -match '(?i)Known SHA256|Windows Defender detection|Windows Defender historical detection'){return 'Very High'}

  $independent=0

  if($confidenceEvidence -match '(?i)Roblox process|Roblox module|Process/file correlation|Independent evidence'){ $independent++ }

  if($confidenceEvidence -match '(?i)Behavior indicators|Behavior:|inject|hook|remote thread|writeprocessmemory'){$independent++}

  if($confidenceEvidence -match '(?i)SHA256|signature|baseline|PE filename'){$independent++}

  if($confidenceEvidence -match '(?i)Prefetch|UserAssist|Amcache|Shimcache|Event Log|RunMRU|Recycle Bin|Cache Artifact|Historical artifact correlation'){$independent++}

  # High confidence requires multiple independent evidence classes AND
  # a meaningful score; a score alone never creates High confidence.
  if($independent -ge 3 -and $Score -ge 12){return 'High'}

  if($independent -ge 2 -and $Score -ge 10){return 'High'}

  if($independent -ge 2 -and $Score -ge 8){return 'Medium'}

  if($independent -ge 1 -and $Score -ge 8){return 'Medium'}

  return 'Low'

}

function Get-ProcessMap {

  param([object[]]$Processes)

  $map = @{}

  foreach ($p in $Processes) { $map[[int]$p.ProcessId] = $p }

  return $map

}

function Get-ParentChain {

  param([int]$ProcessId,[hashtable]$Map,[int]$MaxDepth=5)

  $names = [System.Collections.Generic.List[string]]::new()

  $current = $ProcessId

  for($i=0;$i -lt $MaxDepth;$i++){

      if(-not $Map.ContainsKey($current)){break}

      $p=$Map[$current]

      $ppid=[int]$p.ParentProcessId

      if($ppid -eq $current -or $ppid -le 0){break}

      if(-not $Map.ContainsKey($ppid)){break}

      [void]$names.Add([string]$Map[$ppid].Name)

      $current=$ppid

  }

  return @($names)

}

function Load-FileBaseline {

  param([string]$Path)

  $out = @{}

  try {

      if (Test-Path -LiteralPath $Path -PathType Leaf) {

          $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop

          if ([string]::IsNullOrWhiteSpace([string]$raw)) {
              $script:baselineLoadFailed = $true
              return $out
          }

          if ($raw) {

              $doc = $raw | ConvertFrom-Json -ErrorAction Stop

              $items = if ($doc.Entries) { @($doc.Entries) } else { @($doc) }

              foreach ($item in $items) {

                  if ($item.Path) {

                      $normalized=[string]$item.Path

                      try{$normalized=[System.IO.Path]::GetFullPath($normalized)}catch{}

                      $out[$normalized] = $item

                  }

              }

              if($out.Count -eq 0){$script:baselineLoadFailed=$true}

          }

      }

  } catch {
      $script:baselineLoadFailed = $true
  }

  return $out

}

function Save-FileBaseline {

  param([hashtable]$Baseline,[string]$Path)

  try {

      $dir = Split-Path $Path -Parent

      if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

      $doc = [PSCustomObject]@{Version=4;ScannerVersion=$scriptVersion;UpdatedUtc=(Get-Date).ToUniversalTime().ToString('o');Entries=@($Baseline.Values)}

      $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"

      $json = $doc | ConvertTo-Json -Depth 6

      [System.IO.File]::WriteAllText($tmp,$json,(New-Object System.Text.UTF8Encoding($false)))

      Move-Item -LiteralPath $tmp -Destination $Path -Force

      return $true

  } catch { return $false }

}

function Add-IntegrityResult {

  param([object]$Identity,[string]$Type,[string]$Details,[int]$Score,[string]$Evidence)

  if (-not $Identity) { return }

  $matched=@(Get-MatchedKeywords "$($Identity.Name) $($Identity.Path) $($Identity.OriginalFilename) $($Identity.Company) $($Identity.Product)")

  $score=[Math]::Min(25,[Math]::Max(0,$Score))

  Add-Result $Type $Identity.Name $Identity.Path $Details (Get-SeverityFromScore $score) $score (Get-Confidence $score $Evidence) ($matched -join ', ') $Evidence

}

function Test-FileIntegrity {

  param([hashtable]$Previous,[hashtable]$Current)

  if ($Previous.Count -eq 0) { return }

  $hashToCurrent = @{}

  foreach ($cur in $Current.Values) {

      if ($cur.SHA256) {

          $hash=[string]$cur.SHA256

          if (-not $hashToCurrent.ContainsKey($hash)) { $hashToCurrent[$hash]=[System.Collections.Generic.List[object]]::new() }

          [void]$hashToCurrent[$hash].Add($cur)

      }

  }

  foreach ($cur in $Current.Values) {

      $old=$Previous[[string]$cur.Path]

      if ($old -and $old.SHA256 -and $cur.SHA256 -and [string]$old.SHA256 -ne [string]$cur.SHA256) {

          $score=2

          if ($cur.Signature -eq 'NotSigned') { $score+=1 }

          if ((Get-PathRisk $cur.Path) -gt 0) { $score+=1 }

          if ($cur.SHA256 -and $knownCheatHashes.Contains([string]$cur.SHA256)) { $score+=12 }

          $matched=@(Get-MatchedKeywords "$($cur.Name) $($cur.Path) $($cur.OriginalFilename) $($cur.Company) $($cur.Product)")

          if ($matched.Count) { $score+=2 }

          # A changed hash alone is not a compromise signal.
          if ($score -lt 4 -and $cur.Signature -ne 'NotSigned' -and -not $matched.Count) { $score=1 }

          Add-IntegrityResult $cur 'File Replaced' "Previous SHA256: $($old.SHA256) | Current SHA256: $($cur.SHA256)" $score 'Baseline path unchanged but file content hash changed'

      }

      if ($cur.OriginalFilename -and $cur.Name) {

          $original=[System.IO.Path]::GetFileName([string]$cur.OriginalFilename)

          if ($original -and $original -ne $cur.Name -and $cur.Name -notmatch '(?i)^Roblox') {

              $score=2

              if ($cur.Signature -eq 'NotSigned') { $score+=2 }

              if ((Get-PathRisk $cur.Path) -gt 0) { $score+=2 }

              if ($cur.SHA256 -and $knownCheatHashes.Contains([string]$cur.SHA256)) { $score+=12 }

              $matched=@(Get-MatchedKeywords "$($cur.Name) $($cur.Path) $($cur.OriginalFilename) $($cur.Company) $($cur.Product)")

              if ($matched.Count) { $score+=2 }

              if ($score -ge 6) { Add-IntegrityResult $cur 'PE Masquerading' "Current name: $($cur.Name) | PE OriginalFilename: $($cur.OriginalFilename)" $score 'PE filename mismatch with additional risk evidence' }

          }

      }

  }

  foreach ($old in $Previous.Values) {

      $oldPath=[string]$old.Path

      if ($Current.ContainsKey($oldPath)) { continue }

      $replacement=$null

      if ($old.SHA256 -and $hashToCurrent.ContainsKey([string]$old.SHA256)) {

          foreach ($candidate in $hashToCurrent[[string]$old.SHA256]) {

              if ([string]$candidate.Path -ne $oldPath) { $replacement=$candidate; break }

          }

      }

      if ($replacement) {

          Add-IntegrityResult $replacement 'File Moved/Renamed' "Previous path: $oldPath | Current path: $($replacement.Path) | SHA256: $($replacement.SHA256)" 7 'Same SHA256 moved to a different path; identity is hash-based and does not imply maliciousness'

      } elseif ($old.Extension -in @('.exe','.dll','.sys','.bat','.cmd','.ps1','.vbs','.js','.lua','.luau')) {

          Add-Result 'Baseline Missing File' $old.Name $oldPath "Previous SHA256: $($old.SHA256)" 'INFO' 1 'Low' '' 'Baseline file missing'

      }

  }

}

function Get-HistoricalArtifactText {

  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

  $matches = [System.Collections.Generic.List[object]]::new()

  foreach ($m in $highRegex.Matches($Text)) { [void]$matches.Add([PSCustomObject]@{Keyword=$m.Value.ToLowerInvariant();Tier='High'}) }

  foreach ($m in $mediumRegex.Matches($Text)) { [void]$matches.Add([PSCustomObject]@{Keyword=$m.Value.ToLowerInvariant();Tier='Medium'}) }

  if ($genericRegex.IsMatch($Text) -and $genericContextRegex.IsMatch($Text)) {

      foreach ($m in $genericRegex.Matches($Text)) { [void]$matches.Add([PSCustomObject]@{Keyword=$m.Value.ToLowerInvariant();Tier='Generic'}) }

  }

  return @($matches | Sort-Object Keyword -Unique)

}

function Add-HistoricalEvidence {

  param([string]$Source,[string]$Name,[string]$Path,[string]$Details,[string]$EvidenceText,[string]$ObservedTime='', [string]$ArtifactKind='')

  $combined = "$Name $Path $Details $EvidenceText"

  $matched = @(Get-HistoricalArtifactText $combined)

  $behavior = @(Get-MatchedBehavior $combined)

  # Do not turn every execution-history artifact into a finding. Require an actual
  # cheat keyword or multiple behavior indicators before scoring historical data.

  if($matched.Count -eq 0 -and $behavior.Count -lt 2){return}

  $execution = $false

  if($Source -match '(?i)(Prefetch|UserAssist|Amcache|Shimcache|Recent|Jump List|RunMRU|Event Log|Defender|Recycle Bin|Process Creation|Execution)'){$execution=$true}
  $score=0
  $pathRisk=Get-PathRisk $Path
  $strongBehaviorCount=@($behavior | Where-Object {$_ -in @('loadlibrary','writeprocessmemory','createremotethread','ntwritevirtualmemory','mapviewofsection','queueuserapc','setwindowshook','openprocess','virtualalloc','virtualprotect')}).Count

  if($execution){$score+=3}

  if($Source -match '(?i)Recycle Bin|Cache'){$score=[Math]::Max(0,$score-2)}

  if($behavior.Count -gt 0 -and $pathRisk -gt 0){$score+=1}

  if($strongBehaviorCount -ge 2){$score+=3}elseif($strongBehaviorCount -eq 1){$score+=1}

  if($behavior.Count -ge 4){$score+=1}

  if($matched.Count -gt 0){

      $tier=Get-KeywordTier @($matched|ForEach-Object Keyword)

      if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}

  }

  if($combined -match '(?i)(\\Users\\[^\\]+\\(Downloads|Desktop|AppData)|\\ProgramData\\|\\Temp\\)'){$score+=2}

  if($EvidenceText -match '(?i)(process creation|process id|parent process|image path|command line|execution|prefetch|userassist|amcache|shimcache|jump list|lnk|defender|deleted|recycle bin)'){$score+=2}

  if($score -le 0){return}

  $score=[Math]::Min(10,$score)

  $confidence=if($Source -match '(?i)Defender' -or ($execution -and $behavior.Count -ge 2 -and $score -ge 10)){'Very High'}elseif($execution -and $score -ge 8){'High'}elseif($score -ge 6){'Medium'}else{'Low'}

  $classification=if($execution -and $score -ge 8){'Executed / strong historical evidence'}elseif($execution){'Execution-related historical evidence'}else{'Historical presence indicator'}

  $detailsOut="Source: $Source | Classification: $classification"

  if($ObservedTime){$detailsOut += " | Observed: $ObservedTime"}

  if($ArtifactKind){$detailsOut += " | Artifact: $ArtifactKind"}

  if($Details){$detailsOut += " | $Details"}

  $keywordText=if($matched.Count){($matched|ForEach-Object Keyword)-join ', '}else{''}

  $safeEvidence=[string]$EvidenceText

  $safeEvidence=Get-ConciseEvidence $EvidenceText 1200

  $evidenceOut="Historical evidence: $safeEvidence"

  if($behavior.Count){$evidenceOut += "; Behavior: $($behavior -join ', ')"}

  Add-Result 'Historical Artifact' $Name $Path $detailsOut (Get-SeverityFromScore $score) $score $confidence $keywordText $evidenceOut

  $script:counts.Historical++

}

function Scan-HistoricalFile {

  param([string]$Path,[string]$Source,[int]$MaxBytes=10485760,[int]$MaxHits=200)

  try {

      if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

      $item = Get-Item -LiteralPath $Path -ErrorAction Stop

      if ($item.Length -gt $MaxBytes) { return }

      $hits=0

      # Historical text files (mainly PSReadLine history) are evaluated line-by-line.

      # This avoids copying multi-megabyte history into a single finding/report entry.

      foreach($line in Get-Content -LiteralPath $Path -ErrorAction Stop){

          if($hits -ge $MaxHits -or (Get-Date) -gt $scanDeadline){break}

          $text=[string]$line

          if([string]::IsNullOrWhiteSpace($text)){continue}

          $km=@(Get-MatchedKeywords $text)

          $bm=@(Get-MatchedBehavior $text)

          if($km.Count -eq 0 -and $bm.Count -lt 2){continue}

          Add-HistoricalEvidence $Source (Split-Path $Path -Leaf) $Path '' $text

          $hits++

      }

  } catch {}

}

function Get-RegistryArtifactText {

  param([string[]]$RegistryPaths)

  foreach ($regPath in $RegistryPaths) {

      try {

          if (-not (Test-Path $regPath)) { continue }

          $keys = if ($regPath -match '\\Uninstall$') { @(Get-ChildItem $regPath -ErrorAction SilentlyContinue) } else { @($regPath) }

          foreach ($key in $keys) {

              $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue

              foreach ($prop in $props.PSObject.Properties) {

                  if ($prop.Name -like 'PS*') { continue }

                  $text = "$($prop.Name) $($prop.Value)"

                  if ((Get-MatchedKeywords $text).Count) { Add-HistoricalEvidence 'Registry historical artifact' ([string]$prop.Name) $key.PSPath ([string]$prop.Value) $text }

              }

          }

      } catch {}

  }

}

function Get-AmcacheEvidence {

  # Amcache.hve is a binary registry hive. Reading it with Get-Content -Raw creates
  # binary garbage, huge evidence strings and false matches. Skip raw parsing here;
  # use event/process/prefetch/registry evidence which can be interpreted reliably.

  return

}

function Get-RecentLinkEvidence {

  $recentItemsProcessed=0
  $roots = @("$env:APPDATA\Microsoft\Windows\Recent")

  foreach ($root in $roots) {

      try {

          if (-not (Test-Path -LiteralPath $root)) { continue }

          foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue) {

              if ((Get-Date) -gt $scanDeadline -or $recentItemsProcessed -ge 5000) { return }
              $recentItemsProcessed++

              $content = ''

              try {

                  if ($item.Extension -ieq '.lnk') {

                      $shell = New-Object -ComObject WScript.Shell

                      $shortcut = $shell.CreateShortcut($item.FullName)

                      $content = "$($shortcut.TargetPath) $($shortcut.Arguments) $($shortcut.WorkingDirectory)"

                  } else { $content = [System.IO.Path]::GetFileNameWithoutExtension($item.Name) }

              } catch {}

              Add-HistoricalEvidence 'Recent / Jump List' $item.Name $item.FullName '' $content $item.LastWriteTime.ToString('o')

          }

      } catch {}

  }

}

function Get-UserAssistEvidence {

  $userAssistKeysProcessed=0
  try {

      $root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

      if (-not (Test-Path $root)) { return }

      foreach ($key in Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue) {

          if ((Get-Date) -gt $scanDeadline) { return }
          $userAssistKeysProcessed++
          if($userAssistKeysProcessed -gt $maxUserAssistKeys){ return }

          $props=Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue

          foreach ($prop in $props.PSObject.Properties) {

              if ($prop.Name -like 'PS*') { continue }

              $text="$($prop.Name) $($prop.Value)"

              if ((Get-MatchedKeywords $text).Count) { Add-HistoricalEvidence 'UserAssist' ([string]$prop.Name) $key.PSPath ([string]$prop.Value) $text }

          }

      }

  } catch {}

}

function Get-ShimcacheEvidence {

  foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatFlags')) {

      try {

          if (-not (Test-Path $path)) { continue }

          $item=Get-ItemProperty $path -ErrorAction SilentlyContinue

          foreach ($prop in $item.PSObject.Properties) {

              if ($prop.Name -like 'PS*') { continue }

              $text="$($prop.Name) $($prop.Value)"

              if ((Get-MatchedKeywords $text).Count) { Add-HistoricalEvidence 'Shimcache / AppCompat' ([string]$prop.Name) $path '' $text }

          }

      } catch {}

  }

}

function Get-DefenderHistoricalEvidence {

  try {

      foreach ($threat in @(Get-MpThreatDetection -ErrorAction SilentlyContinue)) {

          $name=[string]$threat.ThreatName

          $resources=[string]$threat.Resources

          $text="$name $resources"

          if ((Get-MatchedKeywords $text).Count -or $name -match '(?i)(hacktool|cheat|executor|exploit|inject)') {

              Add-Result 'Historical Defender Artifact' $name $resources "Initial detection: $($threat.InitialDetectionTime)" 'HIGH' 15 'Very High' '' 'Windows Defender historical detection'

              $script:counts.Historical++

          }

      }

  } catch {}

}

function Get-EventHistoricalEvidence {

  param([string[]]$Logs)

  foreach ($log in $Logs) {

      if ((Get-Date) -gt $scanDeadline) { return }

      try {

          $events=Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1000 -ErrorAction SilentlyContinue

          foreach ($evt in $events) {

              if ((Get-Date) -gt $scanDeadline) { return }

              $msg=[string]$evt.Message

              $matched=@(Get-HistoricalArtifactText $msg)

              if ($matched.Count) {

                  Add-HistoricalEvidence 'Windows Event Log' "Event ID $($evt.Id)" $log $msg.Substring(0,[Math]::Min(700,$msg.Length)) $msg $evt.TimeCreated.ToString('o')

              }

          }

      } catch {}

  }

}

function Get-PowerShellHistoricalEvidence {

  foreach ($path in @("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\VisualStudio_code_history.txt")) {

      Scan-HistoricalFile $path 'PowerShell history'

  }

}

function Get-PrefetchHistoricalEvidence {

  $path='C:\Windows\Prefetch'

  try {

      if (-not (Test-Path $path)) { return }

      foreach ($item in @(Get-ChildItem $path -Filter '*.pf' -File -ErrorAction SilentlyContinue)) {

          if ((Get-Date) -gt $scanDeadline) { return }

          $matched=@(Get-HistoricalArtifactText $item.Name)

          if ($matched.Count) { Add-HistoricalEvidence 'Prefetch' $item.Name $item.FullName 'Execution-history artifact' $item.Name $item.LastWriteTime.ToString('o') }

      }

  } catch {}

}

function Get-RecycleBinEvidence {

  try {

      $driveRoots=@()

      try {

          $driveRoots=@(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {

              if($_.DeviceID){ Join-Path $_.DeviceID '\$Recycle.Bin' }

          })

      } catch {}

      if(-not $driveRoots.Count){$driveRoots=@('C:\$Recycle.Bin')}

      $seenRecycleRoots=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

      $recycleItems=0

      $maxRecycleItems=3000

      foreach($recycleRoot in $driveRoots){

          if(-not $seenRecycleRoots.Add([string]$recycleRoot)){continue}

          $roots=Get-ChildItem -LiteralPath $recycleRoot -Force -Directory -ErrorAction SilentlyContinue

          foreach($root in @($roots)){

              foreach($item in Get-ChildItem -LiteralPath $root.FullName -Force -File -ErrorAction SilentlyContinue){

                  if((Get-Date)-gt $scanDeadline -or $recycleItems -ge $maxRecycleItems){return}

                  $recycleItems++

                  $name=$item.Name

                  $sidecar=$name -match '^\$I'

                  $text=$name

                  if($sidecar){

                      try{$text += ' '+(Get-Content -LiteralPath $item.FullName -Raw -ErrorAction Stop)}catch{}

                  }

                  $before=$results.Count

                  Add-HistoricalEvidence 'Recycle Bin' $name $item.FullName 'Deleted-file metadata' $text $item.LastWriteTime.ToString('o') 'Deleted file / recycle metadata'

                  if($results.Count -gt $before){$script:counts.RecycleBin++}

              }

          }

      }

  } catch {}

}

function Get-CacheEvidence {

  $cacheRoots=@(

      @{Path=$env:TEMP;Kind='Windows user Temp/cache'},

      @{Path=(Join-Path $env:LOCALAPPDATA 'Temp');Kind='Windows Local Temp/cache'},

      @{Path=(Join-Path $env:LOCALAPPDATA 'Roblox');Kind='Roblox cache'},

      @{Path=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Cache');Kind='Chrome cache'},

      @{Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Cache');Kind='Edge cache'},

      @{Path=(Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles');Kind='Firefox cache'}

  )

  $seenCacheRoots=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  $totalItems=0

  $maxItems=2000

  foreach($entry in $cacheRoots){

      if((Get-Date)-gt $scanDeadline -or $totalItems -ge $maxItems){return}

      $root=[string]$entry.Path

      if([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)){continue}

      if(-not $seenCacheRoots.Add($root)){continue}

      try{

          foreach($item in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue){

              if((Get-Date)-gt $scanDeadline -or $totalItems -ge $maxItems){return}

              $totalItems++

              $name=[string]$item.Name

              $full=[string]$item.FullName

              $combined="$name $full"

              $matched=@(Get-MatchedKeywords $combined)

              $behavior=@(Get-MatchedBehavior $combined)

              if(-not $matched.Count -and -not $behavior.Count){continue}

              $score=0

              $tier=Get-KeywordTier $matched

              if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}

              if($behavior.Count -ge 2){$score+=2}elseif($behavior.Count -eq 1){$score+=1}

              if($combined -match '(?i)\\Roblox(\\|$)' -or $entry.Kind -eq 'Roblox cache'){$score+=1}

              $score=[Math]::Min(6,$score)

              if($score -lt 3){continue}

              $ev=@("Cache artifact: $($entry.Kind)")

              if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

              if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

              $before=$results.Count

              Add-Result 'Cache Artifact' $name $full "Cache source: $($entry.Kind)" (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

              if($results.Count -gt $before){$script:counts.Cache++}

          }

      } catch {}

  }

}

function Get-ProcessCreationEvidence {

  try {

      foreach($log in @('Security','Microsoft-Windows-Sysmon/Operational')){

          if((Get-Date)-gt $scanDeadline){return}

          try{

              $events=Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=(Get-Date).AddDays(-30);Id=1,4688} -MaxEvents 1500 -ErrorAction SilentlyContinue

              foreach($evt in @($events)){

                  if((Get-Date)-gt $scanDeadline){return}

                  $msg=[string]$evt.Message

                  $image=''

                  if($msg -match '(?im)(?:New Process Name|Image):\s*(.+)$'){$image=$matches[1].Trim()}

                  $cmd=''

                  if($msg -match '(?im)(?:CommandLine|Process Command Line):\s*(.+)$'){$cmd=$matches[1].Trim()}

                  $text="$image $cmd $msg"

                  $matched=@(Get-MatchedKeywords $text)

                  $behavior=@(Get-MatchedBehavior $text)

                  $pathRisk=Get-PathRisk $image

                  $score=0

                  if($image -match '(?i)\.(exe|dll|bat|cmd|ps1|vbs|js)(\s|$)'){$score+=1}
                  if($behavior.Count -gt 0 -and $pathRisk -gt 0){$score+=1}
                  if($behavior.Count -ge 2){$score+=3}

                  if($text -match '(?i)RobloxPlayerBeta|RobloxStudioBeta'){$score+=2}

                  if($score -ge 4 -and ($behavior.Count -gt 0 -or $matched.Count -gt 0)){

                      Add-HistoricalEvidence 'Process Creation' "Event ID $($evt.Id)" $log "Image: $image | CommandLine: $cmd" $text $evt.TimeCreated.ToString('o') 'Windows process-creation telemetry'

                  }

              }

          }catch{}

      }

  } catch {}

}

function Invoke-HistoricalForensics {

  Write-Host ''

  Write-Host '============================================================' -ForegroundColor Cyan

  Write-Host '             HISTORICAL / DELETED ARTIFACTS' -ForegroundColor Cyan

  Write-Host '============================================================' -ForegroundColor Cyan

  Get-AmcacheEvidence

  Get-RecentLinkEvidence

  Get-UserAssistEvidence

  Get-ShimcacheEvidence

  Get-DefenderHistoricalEvidence

  Get-PowerShellHistoricalEvidence

  Get-PrefetchHistoricalEvidence

  Get-RecycleBinEvidence

  Get-CacheEvidence

  Get-ProcessCreationEvidence

  Get-RegistryArtifactText @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

  Get-EventHistoricalEvidence @('Microsoft-Windows-PowerShell/Operational','Security','Microsoft-Windows-Sysmon/Operational')

  Write-Host "      Historical findings: $($counts.Historical)"

}

if(-not (Test-ScannerEnvironment)){ exit 2 }

# Lower scanner priority so normal interactive work remains responsive.

try {

  $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()

  $currentProcess.PriorityClass = [System.Enum]::Parse([System.Diagnostics.ProcessPriorityClass], $scannerPriority)

} catch {}

Write-Host ''

Write-Host '============================================================' -ForegroundColor Cyan

Write-Host "                 FORENSIC SCANNER $scriptVersion" -ForegroundColor Cyan

Write-Host '============================================================' -ForegroundColor Cyan

Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) { Write-Host '[+] Administrator: YES' -ForegroundColor Green } else { Write-Host '[!] Administrator: NO - some telemetry may be unavailable' -ForegroundColor Yellow }

Write-Host "[i] Performance profile: Balanced | File pacing: $fileThrottleMilliseconds ms | Safety deadline: 30 min" -ForegroundColor DarkGray

Write-Host '[i] File and event scans are running in background.' -ForegroundColor DarkGray
Write-Host '[i] Hardened safety mode: bounded queues/findings, paced scanning, suppressed internal output, and rate-limited console status.' -ForegroundColor DarkGray

Write-Host '[i] Multi-signal detection: process context, module loading, hashes, signatures, PE identity, execution artifacts and baseline correlation.' -ForegroundColor DarkGray
Write-Host '[i] File coverage: local user profiles, ProgramData, Program Files, Windows Temp and scheduled-task storage; inaccessible paths are not verified.' -ForegroundColor DarkGray

Write-Host ''

# Expand coverage while avoiding repeated scans of nested AppData/Downloads folders.
# The Users root includes other local profiles and hidden directories; Program Files
# covers installed applications where renamed binaries may be stored.
$fileRoots = @(
  (Join-Path $env:SystemDrive 'Users'),
  $env:ProgramData,
  $env:ProgramFiles,
  ${env:ProgramFiles(x86)},
  (Join-Path $env:WINDIR 'Temp'),
  (Join-Path $env:WINDIR 'System32\Tasks')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
  ForEach-Object { try { [System.IO.Path]::GetFullPath($_).TrimEnd('\') } catch { $_ } } |
  Select-Object -Unique

$baselineEntries = Load-FileBaseline $baselinePath

$baselineInitialized = ($baselineEntries.Count -eq 0 -and -not $baselineLoadFailed)
if($baselineLoadFailed){
  Write-Warning 'Existing baseline could not be read; it will be preserved and not overwritten.'
}

$fileScanScript = {

  param($fileRoots,$highKeywords,$mediumKeywords,$genericKeywords,$behaviorKeywords,$excludedPathPattern,$selfDir,$knownCheatHashesArr,$knownGoodHashesArr,$deadline,$throttleMilliseconds,$burstSize,$allowlistArr,$maxWorkerFindings,$baselineLookup,$baselineNeedsFullHash)

  $highRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($highKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $mediumRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($mediumKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $genericRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($genericKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $behaviorRegex=[regex]::new(($behaviorKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $genericContextRegex=[regex]::new('(?i)(roblox|executor|exploit|inject(?:or)?|loadlibrary|virtualalloc|virtualprotect|writeprocessmemory|createremotethread|setwindowshook|powershell|mshta|rundll32|regsvr32|encodedcommand|downloadstring|frombase64string)',[System.Text.RegularExpressions.RegexOptions]'Compiled')

  $cheatSet=[System.Collections.Generic.HashSet[string]]::new([string[]]$knownCheatHashesArr,[StringComparer]::OrdinalIgnoreCase)

  $goodSet=[System.Collections.Generic.HashSet[string]]::new([string[]]$knownGoodHashesArr,[StringComparer]::OrdinalIgnoreCase)

  $allowlistSet=[System.Collections.Generic.HashSet[string]]::new([string[]]$allowlistArr,[StringComparer]::OrdinalIgnoreCase)

  function TestAllowlistedLocal {

      param([string]$Path,[string]$Hash='',[string]$Publisher='')

      if($Hash -and $allowlistSet.Contains($Hash)){return $true}

      if($Path -and $allowlistSet.Contains($Path)){return $true}

      # PE CompanyName is editable metadata, not a verified signer identity.
      # Only exact file hashes or exact paths may suppress worker findings.
      return $false

  }

  function TestPathExcludedLocal {

      param([string]$Path)

      if([string]::IsNullOrWhiteSpace($Path)){return $false}

      if($excludedPathPattern -and $Path -match $excludedPathPattern){return $true}

      if($selfDir){
          try {
              $normalizedSelf=[System.IO.Path]::GetFullPath($selfDir).TrimEnd('\')
              $normalizedPath=[System.IO.Path]::GetFullPath($Path).TrimEnd('\')
              if([string]::Equals($normalizedPath,$normalizedSelf,[System.StringComparison]::OrdinalIgnoreCase) -or
                 $normalizedPath.StartsWith(($normalizedSelf+'\'),[System.StringComparison]::OrdinalIgnoreCase)){
                  return $true
              }
          } catch {}
      }

      return $false
  }

  $found=[System.Collections.Generic.List[object]]::new()

  $baseline=[System.Collections.Generic.List[object]]::new()

  $hashCacheLocal=@{}

  $scanCompleted=$true
  $script:workerEnumerationErrors=0

  $processedInterestingFiles=0
  $filesVisited=0
  $filesAnalyzed=0

  function MatchLocal {

      param([string]$Text)

      $m=[System.Collections.Generic.List[string]]::new()

      if($highRegex.IsMatch($Text)){foreach($x in $highRegex.Matches($Text)){[void]$m.Add($x.Value.ToLowerInvariant())}}

      if($mediumRegex.IsMatch($Text)){foreach($x in $mediumRegex.Matches($Text)){[void]$m.Add($x.Value.ToLowerInvariant())}}

      if($genericRegex.IsMatch($Text) -and $genericContextRegex.IsMatch($Text)){foreach($x in $genericRegex.Matches($Text)){[void]$m.Add($x.Value.ToLowerInvariant())}}

      @($m|Select-Object -Unique)

  }

  function BehaviorLocal {

      param([string]$Text)

      $m=[System.Collections.Generic.List[string]]::new()

      foreach($x in $behaviorRegex.Matches($Text)){[void]$m.Add($x.Value.ToLowerInvariant())}

      @($m|Select-Object -Unique)

  }

  function BinaryIndicatorsLocal {

      param([string]$Path,[int64]$MaxBytes=4194304)

      try {
          $fs=[System.IO.File]::Open($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
          try {
              $length=[int64]$fs.Length
              if($length -le 0){return @()}
              if($length -le $MaxBytes){$windowSize=[int]$length;$offsets=@([int64]0)}
              else {
                  $windowSize=[int][Math]::Max(1,[Math]::Floor($MaxBytes/5))
                  $last=[int64]($length-$windowSize)
                  $offsets=@([int64]0,[int64][Math]::Max(0,[Math]::Floor($last*0.25)),[int64][Math]::Max(0,[Math]::Floor($last*0.50)),[int64][Math]::Max(0,[Math]::Floor($last*0.75)),$last) | Select-Object -Unique
              }
              $builder=[System.Text.StringBuilder]::new()
              foreach($offset in $offsets){
                  [void]$fs.Seek([int64]$offset,[System.IO.SeekOrigin]::Begin)
                  $count=[int][Math]::Min($windowSize,$length-$offset)
                  if($count -le 0){continue}
                  $buffer=New-Object byte[] $count
                  $read=0
                  while($read -lt $count){$chunk=$fs.Read($buffer,$read,$count-$read);if($chunk -le 0){break};$read+=$chunk}
                  if($read -gt 0){[void]$builder.Append([System.Text.Encoding]::ASCII.GetString($buffer,0,$read));[void]$builder.Append(' ');[void]$builder.Append([System.Text.Encoding]::Unicode.GetString($buffer,0,$read))}
              }
              @(BehaviorLocal $builder.ToString() | Where-Object {$_ -in @('loadlibrary','writeprocessmemory','createremotethread','ntwritevirtualmemory','mapviewofsection','queueuserapc','setwindowshook','openprocess','virtualalloc','virtualprotect')} | Select-Object -Unique)
          } finally { $fs.Dispose() }
      } catch { return @() }

  }

  function PathRiskLocal {

      param([string]$Path)

      if($Path -match '(?i)\\(Downloads|Desktop|Temp|AppData\\(Local|Roaming)|ProgramData|Windows\\Temp)\\'){return 2}

      return 0

  }

  function GetSignatureInfoLocal {

      param([string]$Path)

      # Query Authenticode only once per file. The previous implementation called
      # Get-AuthenticodeSignature twice for every valid binary (status, then signer).
      try {
          $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
          $subject=''
          if($signature.Status -eq 'Valid' -and $signature.SignerCertificate){
              $subject=[string]$signature.SignerCertificate.Subject
          }
          return [PSCustomObject]@{Status=[string]$signature.Status;SignerSubject=$subject}
      } catch {
          return [PSCustomObject]@{Status='';SignerSubject=''}
      }

  }

  function ReadScriptLocal {

      param([string]$Path,[int64]$Length)

      if($Length -gt 1048576){return ''}

      try { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop } catch { return '' }

  }

  function EnumerateFilesLocal {

      param([string]$Root,[datetime]$Deadline)

      $stack=[System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()

      try{$stack.Push([System.IO.DirectoryInfo]::new($Root))}catch{$script:workerEnumerationErrors++;return}

      while($stack.Count -gt 0){

          if((Get-Date) -gt $Deadline){return}

          $dir=$stack.Pop()

          try{

              foreach($file in $dir.EnumerateFiles('*',[System.IO.SearchOption]::TopDirectoryOnly)){

                  if((Get-Date) -gt $Deadline){return}

                  if(-not ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint)){Write-Output $file}

              }

              foreach($subdir in $dir.EnumerateDirectories('*',[System.IO.SearchOption]::TopDirectoryOnly)){

                  if((Get-Date) -gt $Deadline){return}

                  if(-not ($subdir.Attributes -band [System.IO.FileAttributes]::ReparsePoint)){

                      $stack.Push($subdir)

                  }

              }

          }catch{$script:workerEnumerationErrors++}

      }

  }

  function MakeIdentity {

      param($item,$hash,$sig,$v)

      [PSCustomObject]@{

          Path=$item.FullName

          Name=$item.Name

          Extension=$item.Extension.ToLowerInvariant()

          Length=[int64]$item.Length

          CreationTimeUtc=$item.CreationTimeUtc.ToString('o')

          LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')

          SHA256=$hash

          Company=if($v){[string]$v.CompanyName}else{''}

          Product=if($v){[string]$v.ProductName}else{''}

          Description=if($v){[string]$v.FileDescription}else{''}

          OriginalFilename=if($v){[string]$v.OriginalFilename}else{''}

          ProductVersion=if($v){[string]$v.ProductVersion}else{''}

          FileVersion=if($v){[string]$v.FileVersion}else{''}

          Signature=$sig

      }

  }

  foreach($root in $fileRoots){

      if((Get-Date)-gt $deadline){$scanCompleted=$false;break}

      try{

          if(-not(Test-Path -LiteralPath $root -PathType Container)){$scanCompleted=$false;$script:workerEnumerationErrors++;continue}

          foreach($item in EnumerateFilesLocal $root $deadline){

              if((Get-Date)-gt $deadline){$scanCompleted=$false;break}
              $filesVisited++

              $path=$item.FullName

              if(TestPathExcludedLocal $path){continue}

              $ext=$item.Extension.ToLowerInvariant()

              $isBinary=$ext -in @('.exe','.dll','.sys')

              $isScript=$ext -in @('.bat','.cmd','.ps1','.vbs','.js','.lua','.luau')

              $isLink=$ext -eq '.lnk'

              $interesting=$isBinary -or $isScript -or $isLink

              if(-not $interesting){continue}

              $hash='';$sig='';$signerSubject='';$v=$null;$content='';$extra='';$details=@()
              $old=$null
              if($baselineLookup -and $baselineLookup.ContainsKey($path)){$old=$baselineLookup[$path]}
              $unchangedFromBaseline=$old -and ([int64]$old.Length -eq [int64]$item.Length) -and ([string]$old.LastWriteTimeUtc -eq $item.LastWriteTimeUtc.ToString('o'))

              # Cheap triage first. Deep work (hash/signature/PE parsing) is delayed
              # until the file is new/changed or has a meaningful suspicious indicator.
              $quickText="$($item.Name) $path"
              $quickMatched=@(MatchLocal $quickText)
              $quickBehavior=@(BehaviorLocal $quickText)
              $quickPathRisk=PathRiskLocal $path
              $quickSuspicious=($quickMatched.Count -gt 0 -or $quickBehavior.Count -gt 0 -or $item.Name -match '(?i)roblox')
              $needsDeep=$baselineNeedsFullHash -or -not $unchangedFromBaseline -or $quickSuspicious

              # PE metadata remains collected for every binary during the baseline
              # pass. Authenticode verification is deferred for ordinary binaries on
              # that first pass; SHA256 and binary-string checks still run for all
              # eligible binaries, and suspicious/changed binaries retain full checks.
              # If the initial baseline deferred this ordinary file's signature,
              # verify it on the next scan instead of reusing an empty value forever.
              $signatureNeedsVerification=(
                  $quickSuspicious -or
                  ((-not $baselineNeedsFullHash) -and (-not $unchangedFromBaseline)) -or
                  ($old -and [string]::IsNullOrWhiteSpace([string]$old.Signature))
              )
              if($isBinary -and $needsDeep){
                  try{$v=$item.VersionInfo;$extra="$($v.CompanyName) $($v.ProductName) $($v.FileDescription) $($v.OriginalFilename)";if($v.CompanyName){$details+="Company: $($v.CompanyName)"};if($v.ProductName){$details+="Product: $($v.ProductName)"};if($v.OriginalFilename){$details+="OriginalFilename: $($v.OriginalFilename)"}}catch{}
              } elseif($isBinary -and $unchangedFromBaseline){
                  $extra="$($old.Company) $($old.Product) $($old.Description) $($old.OriginalFilename)"
              } elseif($isScript){
                  # Scripts are cheap to inspect and often carry the strongest behavior signal.
                  $content=ReadScriptLocal $path $item.Length
                  if($content){$extra=$content}
              } elseif($isLink){
                  try{$shell=New-Object -ComObject WScript.Shell;$shortcut=$shell.CreateShortcut($path);$extra="$($shortcut.TargetPath) $($shortcut.Arguments) $($shortcut.WorkingDirectory)"}catch{}
              }

              if($baselineNeedsFullHash -or -not $unchangedFromBaseline -or $quickSuspicious){
                  $hashKey="$path|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
                  if($hashCacheLocal.ContainsKey($hashKey)){
                      $hash=$hashCacheLocal[$hashKey]
                  } else {
                      try{$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()}catch{$hash=''}
                      $hashCacheLocal[$hashKey]=$hash
                  }
              } elseif($old -and $old.SHA256){
                  $hash=[string]$old.SHA256
              }

              $publisher=if($v){[string]$v.CompanyName}elseif($old){[string]$old.Company}else{''}
              $originalFilename=if($v){[string]$v.OriginalFilename}elseif($old){[string]$old.OriginalFilename}else{''}

              # Reuse the previous signature for unchanged files. Verify signatures only
              # for new/changed files or when cheap triage already found something interesting.
              if($isBinary -and $signatureNeedsVerification){
                  $signatureInfo=GetSignatureInfoLocal $path
                  $sig=[string]$signatureInfo.Status
                  $signerSubject=[string]$signatureInfo.SignerSubject
              } elseif($old -and $old.Signature){
                  $sig=[string]$old.Signature
              }

              if($v -and $v.OriginalFilename -and $item.Name -and [System.IO.Path]::GetFileName([string]$v.OriginalFilename) -ne $item.Name){$extra += ' PE filename mismatch'}

              $binaryIndicators=@()
              if($isBinary -and $needsDeep -and $item.Length -le 67108864){
                  $binaryIndicators=@(BinaryIndicatorsLocal $path)
                  if($binaryIndicators.Count){$extra += ' Binary strings: '+($binaryIndicators -join ', ')}
              }

              $combined="$($item.Name) $path $extra"

              $matched=@(MatchLocal $combined)

              $behavior=@(BehaviorLocal $combined)

              $pathRisk=PathRiskLocal $path

              $publisher=if($v){[string]$v.CompanyName}elseif($old){[string]$old.Company}else{''}

              $originalFilename=if($v){[string]$v.OriginalFilename}elseif($old){[string]$old.OriginalFilename}else{''}

              $score=0

              # Writable location and unsigned state are supporting evidence only.
              if($isBinary -and $sig -eq 'Valid' -and $signerSubject -match '(?i)Microsoft Corporation|Microsoft Windows|Roblox Corporation'){$score-=2}

              $strongBehaviorCount=@($behavior | Where-Object {
                  $_ -in @('loadlibrary','writeprocessmemory','createremotethread',
                           'ntwritevirtualmemory','mapviewofsection','queueuserapc',
                           'setwindowshook','openprocess','virtualalloc','virtualprotect')
              }).Count

              $luaApiIndicators=@($behavior | Where-Object {
                  $_ -in @('getgenv','getrenv','getfenv','hookfunction','hookmetamethod',
                           'getrawmetatable','setreadonly','make_writeable','identifyexecutor',
                           'queue_on_teleport','firetouchinterest','getconnections','getgc',
                           'getinstances','getscripts','getloadedmodules','drawing.new',
                           'syn.request','http_request')
              })
              $luaContext=($ext -in @('.lua','.luau') -and $luaApiIndicators.Count -ge 2)

              if($behavior.Count -ge 2){$score+=2}
              if($luaContext){
                  $score+=4
                  if($luaApiIndicators.Count -ge 4){$score+=2}
              }

              # Strings embedded in a binary do not prove that its code calls those APIs.
              # Keep them weak supporting evidence and require independent context.
              if($binaryIndicators.Count -ge 3 -and ($quickSuspicious -or $path -match '(?i)\\Roblox\\Versions\\')){$score+=1}

              if($behavior.Count -ge 3 -and $strongBehaviorCount -ge 1){$score+=1}

              if($hash -and $cheatSet.Contains($hash)){$score+=15}

              if($hash -and $goodSet.Contains($hash)){$score=[Math]::Max(0,$score-10)}

              if($originalFilename -and $item.Name -and [System.IO.Path]::GetFileName($originalFilename) -ne $item.Name){$score+=1}

              if($matched.Count){
                  $tier='Generic'
                  if(@($matched|Where-Object{$highKeywords -contains $_}).Count){$tier='High'}elseif(@($matched|Where-Object{$mediumKeywords -contains $_}).Count){$tier='Medium'}
                  $meaningfulContext=($behavior.Count -gt 0 -or $luaContext -or $path -match '(?i)\\Roblox\\Versions\\' -or $item.Name -match '(?i)Roblox' -or $hash -and $cheatSet.Contains($hash))
                  if($meaningfulContext){if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}}
              }

              $allowlisted=TestAllowlistedLocal -Path $path -Hash $hash -Publisher $publisher

              $score=[Math]::Min(25,[Math]::Max(0,$score))

              $identity=MakeIdentity $item $hash $sig $v
              if($old -and $unchangedFromBaseline){
                  foreach($prop in @('SHA256','Company','Product','Description','OriginalFilename','ProductVersion','FileVersion','Signature')){
                      if($old.PSObject.Properties[$prop]){$identity.$prop=$old.$prop}
                  }
              }

              [void]$baseline.Add($identity)
              $filesAnalyzed++

              if($allowlisted){continue}

              if($score -ge 6 -or ($hash -and $cheatSet.Contains($hash)) -or ($behavior.Count -ge 2 -and $quickSuspicious)){

                  $e=@()

                  if($matched.Count){$e+="Keyword: $($matched -join ', ')"}

                  if($behavior.Count -ge 2){$e+="Behavior indicators: $($behavior -join ', ')"}
                  if($luaContext){$e+="Roblox Lua executor API indicators: $($luaApiIndicators -join ', ')"}
                  if($binaryIndicators.Count -ge 2){$e+="Binary API strings (weak static evidence; not proof of execution): $($binaryIndicators -join ', ')"}

                  if($hash -and $cheatSet.Contains($hash)){$e+='Known SHA256'}

                  if($sig -eq 'NotSigned'){$e+='Unsigned executable'}

                  if($pathRisk -gt 0){$e+='User-writable path'}

                  if($item.LastWriteTime -gt (Get-Date).AddDays(-30) -and $pathRisk -gt 0){$e+='Recent file'}

                  if($content -and $content.Length -gt 0 -and $behavior.Count -gt 0){$e+='Script content indicator'}

                  if($publisher){$e+="Publisher: $publisher"}

                  if($originalFilename -and $item.Name -and [System.IO.Path]::GetFileName($originalFilename) -ne $item.Name){$e+='PE filename mismatch'}

                  $sev=if($score -ge 14){'HIGH'}elseif($score -ge 8){'MEDIUM'}elseif($score -ge 4){'LOW'}else{'INFO'}

                  $independent=0
                  if($hash -and $cheatSet.Contains($hash)){$independent++}
                  if($behavior.Count -ge 2 -or $luaApiIndicators.Count -ge 2){$independent++}
                  if($matched.Count -gt 0 -and $meaningfulContext){$independent++}

                  $conf=if($e -match '(?i)Known SHA256'){'Very High'}elseif($score -ge 10 -and $independent -ge 2){'High'}elseif($score -ge 8 -and $independent -ge 1){'Medium'}else{'Low'}

                  $workerFinding=[PSCustomObject]@{Name=$item.Name;FullName=$path;Hash=$hash;Signature=$sig;Details=(($details+$(if($hash){"SHA256: $hash"})+$(if($sig){"Signature: $sig"})) -join ' | ');Score=$score;Severity=$sev;Confidence=$conf;Keyword=($matched -join ', ');Evidence=($e -join '; ')}
                  if($found.Count -lt $maxWorkerFindings){
                      [void]$found.Add($workerFinding)
                  } else {
                      $weakest=$found | Sort-Object Score | Select-Object -First 1
                      if($weakest -and [int]$score -gt [int]$weakest.Score){
                          [void]$found.Remove($weakest)
                          [void]$found.Add($workerFinding)
                      }
                  }

              }

              # Pacing happens after a complete file decision, so every eligible file

              # still receives the same detection pipeline in every mode.

              $processedInterestingFiles++

              if($throttleMilliseconds -gt 0 -and $burstSize -gt 0 -and ($processedInterestingFiles % $burstSize) -eq 0){

                  Start-Sleep -Milliseconds $throttleMilliseconds

              }

          }

          if((Get-Date) -gt $deadline){$scanCompleted=$false;break}

      }catch{$script:workerEnumerationErrors++;$scanCompleted=$false}

  }

  if($script:workerEnumerationErrors -gt 0){$scanCompleted=$false}
  [PSCustomObject]@{Findings=$found;Baseline=$baseline;Completed=$scanCompleted;FilesVisited=$filesVisited;FilesAnalyzed=$filesAnalyzed;EnumerationErrors=$script:workerEnumerationErrors}

}

function Get-MonitorIdentityCached {

  param([string]$Path)

  try{

      $item=Get-Item -LiteralPath $Path -ErrorAction Stop

      $key="$Path|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"

      $now=[DateTime]::UtcNow

      if($monitorIdentityCache.ContainsKey($key)){

          $entry=$monitorIdentityCache[$key]

          if(($now-$entry.Time).TotalSeconds -lt $monitorIdentityCacheTtlSeconds){return $entry.Identity}

      }

      $identity=Get-FileIdentity $Path

      if($identity){

          $monitorIdentityCache[$key]=[PSCustomObject]@{Time=$now;Identity=$identity}

          if($monitorIdentityCache.Count -gt 1000){

              foreach($k in @($monitorIdentityCache.Keys)){

                  if(($now-$monitorIdentityCache[$k].Time).TotalSeconds -ge $monitorIdentityCacheTtlSeconds){[void]$monitorIdentityCache.Remove($k)}

              }

          }

      }

      return $identity

  }catch{return $null}

}

function Get-MonitorFileFinding {

  param([string]$Path)

  try{

      if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return $null}

      if(Test-PathExcluded $Path){return $null}

      $item=Get-Item -LiteralPath $Path -ErrorAction Stop

      $ext=$item.Extension.ToLowerInvariant()

      if($ext -notin $highRiskExtensions){return $null}

      $identity=Get-MonitorIdentityCached $Path

      if(-not $identity){return $null}

      if(Test-Allowlisted -Path $Path -Hash $identity.SHA256 -Publisher $identity.Publisher){return $null}

      $content=''

      if($ext -in @('.bat','.cmd','.ps1','.vbs','.js','.lua','.luau')){

          try{if($item.Length -le 1048576){$content=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop}}catch{}

      }

      $extra="$content $($identity.Company) $($identity.Product) $($identity.Description) $($identity.OriginalFilename)"

      $matched=@(Get-MatchedKeywords "$($identity.Name) $Path $extra")

      $behavior=@(Get-MatchedBehavior "$($identity.Name) $Path $extra")
      $binaryIndicators=@()
      if($ext -in @('.exe','.dll','.sys') -and $item.Length -le 67108864){$binaryIndicators=@(Get-BinaryStringIndicators $Path)}

      $score=Get-SuspicionScore -Name $identity.Name -Path $Path -Hash $identity.SHA256 -Signature $identity.Signature -ExtraText $extra -Publisher $identity.Publisher -OriginalFilename $identity.OriginalFilename
      $luaApiIndicators=@($behavior | Where-Object {
          $_ -in @('getgenv','getrenv','getfenv','hookfunction','hookmetamethod',
                   'getrawmetatable','setreadonly','make_writeable','identifyexecutor',
                   'queue_on_teleport','firetouchinterest','getconnections','getgc',
                   'getinstances','getscripts','getloadedmodules','drawing.new',
                   'syn.request','http_request')
      })
      $luaContext=($ext -in @('.lua','.luau') -and $luaApiIndicators.Count -ge 2)
      if($luaContext){$score=[Math]::Min(25,$score+4+$(if($luaApiIndicators.Count -ge 4){2}else{0}))}
      if($binaryIndicators.Count -ge 3 -and ($matched.Count -gt 0 -or $behavior.Count -gt 0 -or (Get-PathRisk $Path) -gt 0)){$score=[Math]::Min(25,$score+1)}

      $e=@()

      if($matched.Count){$e+="Keyword: $($matched -join ', ')"}

      if($behavior.Count){$e+="Behavior: $($behavior -join ', ')"}
      if($luaContext){$e+="Roblox Lua executor API indicators: $($luaApiIndicators -join ', ')"}
      if($binaryIndicators.Count -ge 2){$e+="Binary API strings (weak static evidence; not proof of execution): $($binaryIndicators -join ', ')"}

      if($identity.SHA256 -and $knownCheatHashes.Contains($identity.SHA256)){$e+='Known SHA256'}

      if($identity.Signature -eq 'NotSigned' -and $ext -in @('.exe','.dll','.sys')){$e+='Unsigned executable/module'}

      if((Get-PathRisk $Path) -gt 0){$e+='User-writable path'}

      if($identity.OriginalFilename -and [System.IO.Path]::GetFileName($identity.OriginalFilename) -ne $identity.Name -and $identity.Name -notmatch '(?i)^Roblox'){$e+='PE filename mismatch'}

      if($content -and $behavior.Count){$e+='Script content indicator'}

      if($score -lt 3 -and -not $luaContext -and -not $knownCheatHashes.Contains([string]$identity.SHA256)){return $null}

      [PSCustomObject]@{Name=$identity.Name;Path=$Path;Hash=$identity.SHA256;Signature=$identity.Signature;Score=$score;Severity=(Get-SeverityFromScore $score);Confidence=(Get-Confidence $score ($e -join '; '));Keyword=($matched -join ', ');Evidence=($e -join '; ');Time=(Get-Date)}

  }catch{return $null}

}

function Get-MonitorRobloxModuleFindings {

  param([switch]$BaselineOnly)

  $out=[System.Collections.Generic.List[object]]::new()

  try{

      $roblox=Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in @('RobloxPlayerBeta','RobloxStudioBeta') }

      $currentKeys=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

      foreach($rp in @($roblox)){

          try{

              foreach($mod in @($rp.Modules)){

                  $path=[string]$mod.FileName

                  if(-not $path){continue}

                  $key="$($rp.Id)|$path"

                  [void]$currentKeys.Add($key)

                  if(-not $monitorSeenModules.Add($key)){continue}

                  if($BaselineOnly){continue}

                  if(($path -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\' -or $path -match $robloxInstallPattern) -and (Get-PathRisk $path) -eq 0){continue}

                  $identity=Get-FileIdentity $path

                  $hash=if($identity){$identity.SHA256}else{Get-FileHashSafe $path}

                  if(Test-Allowlisted -Path $path -Hash $hash){continue}

                  $sig=if($identity){$identity.Signature}else{Get-FileSignatureStatus $path}

                  $publisher=if($identity){$identity.Publisher}else{''}

                  $original=if($identity){$identity.OriginalFilename}else{''}

                  # A module being outside the Roblox folder is common (GPU drivers,
                  # overlays and security software). Location alone must not create a finding.
                  $score=Get-SuspicionScore -Name ([System.IO.Path]::GetFileName($path)) -Path $path -Hash $hash -Signature $sig -Publisher $publisher -OriginalFilename $original

                  $matched=@(Get-MatchedKeywords "$path $publisher $original")

                  $behavior=@(Get-MatchedBehavior "$path $publisher $original")

                  $outsideRoblox=$path -notmatch $robloxInstallPattern
                  $pathRisk=Get-PathRisk $path
                  $metadataMismatch=($original -and [System.IO.Path]::GetFileName($original) -ne [System.IO.Path]::GetFileName($path))
                  $knownBadHash=($hash -and $knownCheatHashes.Contains($hash))
                  $meaningfulContext=($matched.Count -gt 0 -or $behavior.Count -gt 0 -or $knownBadHash -or ($sig -eq 'NotSigned' -and $pathRisk -gt 0) -or ($outsideRoblox -and $metadataMismatch))

                  if($behavior.Count -ge 2){$score+=2}
                  if($sig -eq 'NotSigned' -and $pathRisk -gt 0){$score+=2}
                  if($outsideRoblox -and $metadataMismatch){$score+=2}
                  if($knownBadHash){$score+=10}

                  $score=[Math]::Min(25,$score)

                  if(-not $meaningfulContext -or $score -lt 5){continue}

                  $e=@('Roblox module observed during continuous monitoring')

                  if($outsideRoblox){$e+='Module path outside Roblox installation'}

                  if($sig -eq 'NotSigned'){$e+='Unsigned module'}

                  if($knownBadHash){$e+='Known SHA256'}

                  if($matched.Count){$e+="Keyword: $($matched -join ', ')"}

                  if($behavior.Count){$e+="Behavior: $($behavior -join ', ')"}

                  [void]$out.Add([PSCustomObject]@{Name=[System.IO.Path]::GetFileName($path);Path=$path;Pid=[int]$rp.Id;Hash=$hash;Signature=$sig;Score=$score;Severity=(Get-SeverityFromScore $score);Confidence=(Get-Confidence $score ($e -join '; '));Keyword=($matched -join ', ');Evidence=($e -join '; ');Time=(Get-Date)})

              }

          }catch{}

      }

      foreach($oldKey in @($monitorSeenModules)){

          if(-not $currentKeys.Contains($oldKey)){[void]$monitorSeenModules.Remove($oldKey)}

      }

  }catch{}

  return $out

}

function Get-MonitorProcessFinding {

  param([object]$Process)

  try{

      $path=[string]$Process.ExecutablePath

      if(-not $path){return $null}

      $name=[string]$Process.Name

      $cmd=[string]$Process.CommandLine

      $identity=Get-FileIdentity $path

      $publisher=if($identity){$identity.Publisher}else{''}

      $original=if($identity){$identity.OriginalFilename}else{''}

      $hash=if($identity){$identity.SHA256}else{''}

      $sig=if($identity){$identity.Signature}else{''}

      $score=Get-SuspicionScore -Name $name -Path $path -CommandLine $cmd -Hash $hash -Signature $sig -Publisher $publisher -OriginalFilename $original

      $isRoblox=$name -in $robloxProcessNames

      if($isRoblox){$score=0}

      $matched=@(Get-MatchedKeywords "$name $path $cmd $publisher $original")

      $behavior=@(Get-MatchedBehavior "$name $path $cmd $publisher $original")

      if($isRoblox -and $behavior.Count -eq 0 -and $matched.Count -eq 0){return $null}

      if($score -lt 3 -and -not $isRoblox){return $null}

      $e=@("Process started during monitoring")

      if($matched.Count){$e+="Keyword: $($matched -join ', ')"}

      if($behavior.Count){$e+="Behavior: $($behavior -join ', ')"}

      if($identity -and $sig -eq 'NotSigned'){$e+='Unsigned executable'}

      if((Get-PathRisk $path) -gt 0){$e+='User-writable path'}

      if($hash -and $knownCheatHashes.Contains($hash)){$e+='Known SHA256'}

      [PSCustomObject]@{Name=$name;Path=$path;Pid=[int]$Process.ProcessId;Score=$score;Severity=(Get-SeverityFromScore $score);Confidence=(Get-Confidence $score ($e -join '; '));Keyword=($matched -join ', ');Evidence=($e -join '; ');CommandLine=$cmd;Time=(Get-Date)}

  }catch{return $null}

}

function Start-MonitorWatchers {

  foreach($root in $fileRoots){

      try{

          if(-not(Test-Path -LiteralPath $root -PathType Container)){continue}

          $watcher=New-Object System.IO.FileSystemWatcher

          $watcher.Path=$root

          $watcher.IncludeSubdirectories=$true

          $watcher.NotifyFilter=[System.IO.NotifyFilters]'FileName, CreationTime, LastWrite, Size'

          $watcher.Filter='*'

          # Larger buffer reduces loss during bursts. FileSystemWatcher still has a finite buffer,
          # so an Error event below marks an overflow instead of failing silently.

          $watcher.InternalBufferSize=65536

          $eventContext=[PSCustomObject]@{Queue=$monitorEvents;Extensions=@($highRiskExtensions);ScannerStats=$scanStats}

          $handler={

              try{

                  $eventArgs=$Event.SourceEventArgs

                  $path=[string]$eventArgs.FullPath

                  $ext=[System.IO.Path]::GetExtension($path).ToLowerInvariant()

                  $context=$Event.MessageData

                  if($context -and $ext -in $context.Extensions){

                      $context.Queue.Enqueue([PSCustomObject]@{Kind='File';Path=$path;Change=[string]$eventArgs.ChangeType;Time=Get-Date})

                          while($context.Queue.Count -gt 5000){$discard=$null;if(-not $context.Queue.TryDequeue([ref]$discard)){break}}

                  }

              }catch{}

          }

          $watcherId=[guid]::NewGuid().ToString('N')

          $createdSource="ForensicScanner.$watcherId.Created"

          $changedSource="ForensicScanner.$watcherId.Changed"

          $renamedSource="ForensicScanner.$watcherId.Renamed"

          $errorSource="ForensicScanner.$watcherId.Error"

          $created=Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier $createdSource -MessageData $eventContext -Action $handler

          $changed=Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier $changedSource -MessageData $eventContext -Action $handler

          $renamed=Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier $renamedSource -MessageData $eventContext -Action $handler

          $errorHandler={

              try {

                  $context=$Event.MessageData

                  if($context -and $context.ScannerStats){

                      $context.ScannerStats.WatcherErrors++

                  }

              } catch {}

          }

          $errorWatcherJob=Register-ObjectEvent -InputObject $watcher -EventName Error -SourceIdentifier $errorSource -MessageData $eventContext -Action $errorHandler

          $watcher.EnableRaisingEvents=$true

          [void]$monitorWatchers.Add([PSCustomObject]@{Watcher=$watcher;Created=$created;Changed=$changed;Renamed=$renamed;Error=$errorWatcherJob;CreatedSource=$createdSource;ChangedSource=$changedSource;RenamedSource=$renamedSource;ErrorSource=$errorSource})

      }catch{}

  }

}

function Stop-MonitorWatchers {

  foreach($w in @($monitorWatchers)){

      try{$w.Watcher.EnableRaisingEvents=$false}catch{}

      foreach($source in @($w.CreatedSource,$w.ChangedSource,$w.RenamedSource,$w.ErrorSource)){

          if($source){try{Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue}catch{}}

      }

      foreach($job in @($w.Created,$w.Changed,$w.Renamed,$w.Error)){

          if($job){try{Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}catch{}}

      }

      try{$w.Watcher.Dispose()}catch{}

  }

  $monitorWatchers.Clear()

}

function Write-MonitorState {

  param([object[]]$Findings)

  try{

      $dir=Split-Path $monitorStatePath -Parent

      if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}

      $doc=[PSCustomObject]@{Version=3;ScannerVersion=$scriptVersion;UpdatedUtc=(Get-Date).ToUniversalTime().ToString('o');Findings=@($Findings|Select-Object -Last 500);WatcherErrors=$scanStats.WatcherErrors}

      $tmp="$monitorStatePath.$([guid]::NewGuid().ToString('N')).tmp"

      $json=$doc|ConvertTo-Json -Depth 6

      [System.IO.File]::WriteAllText($tmp,$json,(New-Object System.Text.UTF8Encoding($false)))

      Move-Item -LiteralPath $tmp -Destination $monitorStatePath -Force

  }catch{}

}

function Start-ContinuousMonitoring {

  param([int]$IntervalSeconds=8)

  if($script:monitorStarted){return}

  $script:monitorStarted=$true
  $script:monitorProcessBaselineReady=$false
  $script:monitorModuleBaselineReady=$false
  $monitorSeenProcesses.Clear()
  $monitorSeenFiles.Clear()
  $monitorSeenModules.Clear()
  $monitorIdentityCache.Clear()
  $discardedEvent=$null
  while($monitorEvents.TryDequeue([ref]$discardedEvent)){$discardedEvent=$null}

  $monitorFindings=[System.Collections.Generic.List[object]]::new()

  $nextProcessCheck=Get-Date

  $nextModuleCheck=Get-Date

  $nextStateWrite=(Get-Date).AddMinutes(1)

  $lastConsoleStatus=Get-Date

  Write-Host ''

  Write-Host '============================================================' -ForegroundColor Cyan

  Write-Host '                 CONTINUOUS MONITORING' -ForegroundColor Cyan

  Write-Host '============================================================' -ForegroundColor Cyan

  Write-Host "Monitoring active. Process interval: ${IntervalSeconds}s. Module interval: ${monitorModuleIntervalSeconds}s. Press Ctrl+C to stop." -ForegroundColor Yellow

  Start-MonitorWatchers

  try{

      while($true){

          $now=Get-Date

          if($now -ge $nextProcessCheck){

              try{

                  $currentProcessKeys=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

                  foreach($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)){

                      $processId=[int]$p.ProcessId

                      $creation=[string]$p.CreationDate

                      $processKey="$processId|$creation"

                      [void]$currentProcessKeys.Add($processKey)

                      if($monitorProcessBaselineReady -and $monitorSeenProcesses.Add($processKey)){

                          $finding=Get-MonitorProcessFinding $p

                          if($finding){

                              [void]$monitorFindings.Add($finding)

                              if($monitorFindings.Count -gt 5000){$monitorFindings.RemoveAt(0)}

                          }

                      }else{

                          [void]$monitorSeenProcesses.Add($processKey)

                      }

                  }

                  if($monitorProcessBaselineReady){

                      foreach($oldKey in @($monitorSeenProcesses)){

                          if(-not $currentProcessKeys.Contains($oldKey)){[void]$monitorSeenProcesses.Remove($oldKey)}

                      }

                  }else{

                      $script:monitorProcessBaselineReady=$true

                  }

              }catch{}

              $nextProcessCheck=$now.AddSeconds([Math]::Max(2,$IntervalSeconds))

          }

          if($now -ge $nextModuleCheck){

              try{

                  $moduleFindings=@(Get-MonitorRobloxModuleFindings -BaselineOnly:(-not $monitorModuleBaselineReady))

                  if($monitorModuleBaselineReady){

                      foreach($finding in $moduleFindings){

                          [void]$monitorFindings.Add($finding)

                          if($monitorFindings.Count -gt 5000){$monitorFindings.RemoveAt(0)}

                      }

                  }

                  $script:monitorModuleBaselineReady=$true

              }catch{}

              $nextModuleCheck=$now.AddSeconds([Math]::Max(5,$monitorModuleIntervalSeconds))

          }

          $fileBatch=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

          $evt=$null

          $eventCount=0

          while($eventCount -lt $monitorMaxEventsPerCycle -and $monitorEvents.TryDequeue([ref]$evt)){

              if($evt.Path){[void]$fileBatch.Add([string]$evt.Path)}

              $evt=$null

              $eventCount++

          }

          if($monitorSeenFiles.Count -gt 2000){

              $monitorSeenFiles.Clear()

          }

          $fileFindingCount=0
          foreach($path in @($fileBatch)){

              if($fileFindingCount -ge $monitorMaxFileFindingsPerCycle){break}

              foreach($cacheKey in @($monitorIdentityCache.Keys)){
                  if($cacheKey.StartsWith(($path+'|'),[System.StringComparison]::OrdinalIgnoreCase)){
                      [void]$monitorIdentityCache.Remove($cacheKey)
                  }
              }

              $finding=Get-MonitorFileFinding $path

              if($finding){

                  $fileFindingCount++
                  $findingKey="$($finding.Path)|$($finding.Hash)|$($finding.Score)"

                  if(-not $monitorSeenFiles.Add($findingKey)){continue}

                  [void]$monitorFindings.Add($finding)

                  if($monitorFindings.Count -gt 5000){$monitorFindings.RemoveAt(0)}

              }

          }

          if($monitorFindings.Count -gt 0 -and $now -ge $nextStateWrite){

              Write-MonitorState @($monitorFindings)

              $nextStateWrite=$now.AddMinutes(1)

          }

          if(($now-$lastConsoleStatus).TotalSeconds -ge $monitorConsoleIntervalSeconds){

              Write-Host ("Monitoring active | Events queued: {0} | Findings: {1} | Watchers: {2}" -f $monitorEvents.Count,$monitorFindings.Count,$monitorWatchers.Count) -ForegroundColor DarkGray

              $lastConsoleStatus=$now

          }

          Start-Sleep -Seconds 1

      }

  }finally{

      Stop-MonitorWatchers

      Write-MonitorState @($monitorFindings)

      $script:monitorStarted=$false

      Write-Host ''

      Write-Host "Monitoring stopped. Findings: $($monitorFindings.Count)" -ForegroundColor Cyan

  }

}

$eventLogScript = {

  param($logs,$highKeywords,$mediumKeywords,$genericKeywords,$deadline)

  $highRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($highKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $mediumRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($mediumKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $genericRegex=[regex]::new('(?<![A-Za-z0-9])(?:'+(($genericKeywords|ForEach-Object{[regex]::Escape($_)}) -join '|')+')(?![A-Za-z0-9])',[System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')

  $genericContextRegex=[regex]::new('(?i)(roblox|executor|exploit|inject(?:or)?|loadlibrary|virtualalloc|virtualprotect|writeprocessmemory|createremotethread|setwindowshook|powershell|mshta|rundll32|regsvr32|encodedcommand|downloadstring|frombase64string)',[System.Text.RegularExpressions.RegexOptions]'Compiled')

  $found=[System.Collections.Generic.List[object]]::new()

  $eventsChecked=0

  foreach($log in $logs){

      if((Get-Date)-gt $deadline){break}

      $logHits=0

      try{

          $events=Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1000 -ErrorAction SilentlyContinue

          foreach($evt in $events){

              if((Get-Date)-gt $deadline){break}

              $eventsChecked++

              $msg=[string]$evt.Message

              $m=[System.Collections.Generic.List[string]]::new()

              foreach($x in $highRegex.Matches($msg)){[void]$m.Add($x.Value.ToLowerInvariant())}

              foreach($x in $mediumRegex.Matches($msg)){[void]$m.Add($x.Value.ToLowerInvariant())}

              if($genericRegex.IsMatch($msg) -and $genericContextRegex.IsMatch($msg)){foreach($x in $genericRegex.Matches($msg)){[void]$m.Add($x.Value.ToLowerInvariant())}}

              $matched=@($m|Select-Object -Unique)

              if($matched.Count){

                  $tier=if($matched|Where-Object{$highKeywords -contains $_}){'High'}elseif($matched|Where-Object{$mediumKeywords -contains $_}){'Medium'}else{'Generic'}

                  $hasExecutionContext=$msg -match '(?i)(CommandLine|Process Command Line|New Process Name|Image:|RobloxPlayerBeta|RobloxStudioBeta|\\Users\\[^\\]+\\(Downloads|Desktop|AppData|Temp)\\)'

                  if($tier -ne 'High' -and -not $hasExecutionContext){continue}

                  $score=if($tier -eq 'High'){5}elseif($tier -eq 'Medium'){2}else{1}

                  if($hasExecutionContext){$score+=1}

                  $sev=if($score -ge 7){'MEDIUM'}elseif($score -ge 3){'LOW'}else{'INFO'}

                  $conf=if($tier -eq 'High'){'Medium'}else{'Low'}

                  [void]$found.Add([PSCustomObject]@{Name="Event ID $($evt.Id)";Path=$log;Details="Time: $($evt.TimeCreated) | $($msg.Substring(0,[Math]::Min(500,$msg.Length)))";Score=$score;Severity=$sev;Confidence=$conf;Keyword=($matched -join ', ');Evidence='Event log execution indicator'})

                  $logHits++

                  if($logHits -ge 100){break}

              }

          }

      }catch{}

  }

  return [PSCustomObject]@{Findings=@($found);EventsChecked=$eventsChecked}

}

$fileRS=[runspacefactory]::CreateRunspace()

$fileRS.Open()

$filePS=[powershell]::Create()

$filePS.Runspace=$fileRS

[void]$filePS.AddScript($fileScanScript).AddArgument($fileRoots).AddArgument($highKeywords).AddArgument($mediumKeywords).AddArgument($genericKeywords).AddArgument($behaviorKeywords).AddArgument($excludedPathPattern).AddArgument($selfDir).AddArgument(@($knownCheatHashes)).AddArgument(@($knownGoodHashes)).AddArgument($scanDeadline).AddArgument([int]$fileThrottleMilliseconds).AddArgument([int]$fileBurstSize).AddArgument(@($script:allowlistEntries)).AddArgument([int]$maxWorkerFindings).AddArgument($baselineEntries).AddArgument([bool]$baselineInitialized)

$fileHandle=$filePS.BeginInvoke()

$eventRS=[runspacefactory]::CreateRunspace()

$eventRS.Open()

$eventPS=[powershell]::Create()

$eventPS.Runspace=$eventRS

[void]$eventPS.AddScript($eventLogScript).AddArgument(@('Microsoft-Windows-PowerShell/Operational','Security','Microsoft-Windows-Sysmon/Operational')).AddArgument($highKeywords).AddArgument($mediumKeywords).AddArgument($genericKeywords).AddArgument($scanDeadline)

$eventHandle=$eventPS.BeginInvoke()

Write-Host '[1/13] Registry and persistence' -ForegroundColor Cyan

$script:registryKeysProcessed=0
$registryPaths=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist','HKCU:\Software\Google\Chrome\Extensions')

foreach($base in $registryPaths){

  try{

      if(-not(Test-Path $base)){continue}

      $keys=if($base -match '\\Uninstall$'){(Get-ChildItem $base -ErrorAction SilentlyContinue | Select-Object -First $maxRegistryKeys)}else{@($base)}

      foreach($key in $keys){
          if($script:registryKeysProcessed -ge $maxRegistryKeys){break}
          $script:registryKeysProcessed++

          $props=Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue

          foreach($prop in $props.PSObject.Properties){

              if($prop.Name -like 'PS*'){continue}

              $text="$($prop.Name) $($prop.Value)"

              $matched=@(Get-MatchedKeywords $text)

              $behavior=@(Get-MatchedBehavior $text)

              $value=[string]$prop.Value

              $score=Get-SuspicionScore -Name $prop.Name -Path $key.PSPath -CommandLine $value -ExtraText $text

              if($behavior.Count -ge 2 -and $value -match '(?i)\\(AppData|Temp|Downloads|Desktop)\\'){$score+=2}

              if($value -match '(?i)\\(AppData|Temp|Downloads|Desktop)\\' -and $value -match '(?i)\.(exe|dll|bat|cmd|ps1|vbs|js)'){$score+=2}

              if($score -ge 3){

                  $ev=@()

                  if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

                  if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

                  if($value -match '(?i)\\(AppData|Temp|Downloads|Desktop)\\'){$ev+='User-writable executable target'}

                  Add-Result 'Registry' ([string]$prop.Name) $key.PSPath $value (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

                  $counts.Registry++

              }

          }

      }

  }catch{}

}

Write-Host "      Matches: $($counts.Registry)"

Write-Host '[2/13] Startup folders' -ForegroundColor Cyan

foreach($startup in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")){

  try{

      if(Test-Path $startup){

          foreach($item in Get-ChildItem $startup -Force -File -ErrorAction SilentlyContinue){

              $path=$item.FullName

              $sig=if($item.Extension -match '(?i)^\.(exe|dll|sys)$'){Get-FileSignatureStatus $path}else{''}

              $matched=@(Get-MatchedKeywords "$($item.Name) $path")

              $behavior=@(Get-MatchedBehavior "$($item.Name) $path")

              $score=Get-SuspicionScore -Name $item.Name -Path $path -Signature $sig

              if($matched.Count -or $sig -eq 'NotSigned' -or $behavior.Count){$score+=1}

              if($behavior.Count -ge 2){$score+=2}

              if($score -ge 3){

                  $ev=@()

                  if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

                  if($sig -eq 'NotSigned'){$ev+='Unsigned startup binary'}

                  Add-Result 'Startup Item' $item.Name $path '' (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

                  $counts.Startup++

              }

          }

      }

  }catch{}

}

Write-Host "      Matches: $($counts.Startup)"

Write-Host '[3/13] Running processes and process ancestry' -ForegroundColor Cyan

$procs=@()

try{$procs=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)}catch{}

$procRows=Get-ProcessMap $procs

foreach($p in $procs){

  try{

      $path=[string]$p.ExecutablePath

      $cmd=[string]$p.CommandLine

      $parentObj=$procRows[[int]$p.ParentProcessId]

      $parent=if($parentObj){[string]$parentObj.Name}else{''}

      $chain=@(Get-ParentChain ([int]$p.ProcessId) $procRows 5)

      $hash=if($path){Get-FileHashSafe $path}else{''}

      $sig=if($path){Get-FileSignatureStatus $path}else{''}

      $meta=if($path){Get-PEMetadata $path}else{$null}

      $publisher=if($meta){[string]$meta.Company}else{''}

      $originalFilename=if($meta){[string]$meta.OriginalFilename}else{''}

      $chainText=($chain -join ' -> ')

      $score=Get-SuspicionScore -Name $p.Name -Path $path -CommandLine $cmd -Hash $hash -Signature $sig -ExtraText "Parent:$parent Chain:$chainText" -Publisher $publisher -OriginalFilename $originalFilename

      if($cmd -match '(?i)(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript).*(https?://|\\\\|%temp%|%appdata%|\\temp\\|\\appdata\\)'){$score+=3}

      if($p.Name -ieq 'msiexec.exe' -and $cmd -match '(?i)(/z|/i\s+[^\r\n]*\\(temp|appdata)\\)'){$score+=3}

      if($p.Name -ieq 'wmiprvse.exe' -and $parent -and $parent -notmatch '(?i)^(svchost|services|wininit|wmiprvse|explorer|system)$'){$score+=2}

      $robloxNames=@('RobloxPlayerBeta.exe','RobloxStudioBeta.exe')

      if($parent -in $robloxNames -and $path -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\'){$score+=3}

      if($score -ge 3){

          $matched=@(Get-MatchedKeywords "$($p.Name) $path $cmd")

          $behavior=@(Get-MatchedBehavior "$($p.Name) $path $cmd")

          $ev=@()

          if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

          if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

          if($parent){$ev+="Parent: $parent"}

          if($chainText){$ev+="Parent chain: $chainText"}

          if($sig -eq 'NotSigned'){$ev+='Unsigned executable'}

          if($hash -and $knownCheatHashes.Contains($hash)){$ev+='Known SHA256'}

          if($p.Name -ieq 'msiexec.exe' -and $cmd -match '(?i)(/z|/i\s+[^\r\n]*\\(temp|appdata)\\)'){$ev+='Unusual installer execution'}

          if($p.Name -ieq 'wmiprvse.exe' -and $parent -and $parent -notmatch '(?i)^(svchost|services|wininit|wmiprvse|explorer|system)$'){$ev+='Unusual WMI parent'}

          Add-Result 'Running Process' $p.Name "PID: $($p.ProcessId)" "Path: $path | Parent: $parent | CommandLine: $cmd$(if($hash){" | SHA256: $hash"})$(if($sig){" | Signature: $sig"})" (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

          $counts.Processes++

      }

  }catch{$scanStats.ProcessErrors++}

}

Write-Host "      Matches: $($counts.Processes)"

Write-Host '[4/13] Roblox loaded module check' -ForegroundColor Cyan

try{

  $robloxProcs=@(Get-Process -Name 'RobloxPlayerBeta','RobloxStudioBeta' -ErrorAction SilentlyContinue)

  foreach($rp in $robloxProcs){

      try{$robloxDir=Split-Path $rp.Path -Parent}catch{$robloxDir=''}

      foreach($mod in @($rp.Modules)){

          try{

              $modPath=[string]$mod.FileName

              if([string]::IsNullOrWhiteSpace($modPath)){continue}

              if($modPath -match '(?i)^C:\\Windows\\' -or ($robloxDir -and $modPath.StartsWith($robloxDir,[System.StringComparison]::OrdinalIgnoreCase))){continue}

              $sig=Get-FileSignatureStatus $modPath
              $signerSubject=if($sig -eq 'Valid'){Get-FileSignerSubject $modPath}else{''}

              $hash=Get-FileHashSafe $modPath

              $meta=Get-PEMetadata $modPath

              $publisher=if($meta){[string]$meta.Company}else{''}

              if(Test-Allowlisted -Path $modPath -Hash $hash -Publisher $publisher){continue}

              $originalFilename=if($meta){[string]$meta.OriginalFilename}else{''}

              $matched=@(Get-MatchedKeywords "$($mod.ModuleName) $modPath $publisher $originalFilename")

              $binaryIndicators=@(Get-BinaryStringIndicators $modPath)
              $behavior=@(Get-MatchedBehavior "$($mod.ModuleName) $modPath")

              $pathRisk=Get-PathRisk $modPath
              $robloxContext=$true
              $outsideRobloxPath=($modPath -notmatch $robloxInstallPattern -and $modPath -notmatch '(?i)^C:\\Windows\\')
              $metadataMismatch=($originalFilename -and $mod.ModuleName -and [System.IO.Path]::GetFileName($originalFilename) -ne $mod.ModuleName)
              $meaningfulContext=($behavior.Count -gt 0 -or $matched.Count -gt 0 -or ($hash -and $knownCheatHashes.Contains($hash)) -or ($sig -eq 'NotSigned' -and $pathRisk -gt 0) -or ($outsideRobloxPath -and $metadataMismatch))

              $score=1
              if($meaningfulContext -and $pathRisk -gt 0){$score+=1}
              if($sig -eq 'NotSigned' -and $meaningfulContext){$score+=2}

              if($sig -eq 'Valid' -and $signerSubject -match '(?i)Microsoft Corporation|Microsoft Windows|Roblox Corporation'){$score=[Math]::Max(0,$score-2)}

              if($behavior.Count -ge 2){$score+=2}
              # Static strings in a module are not proof of API use; only add a small
              # supporting point when independent module context already exists.
              if($binaryIndicators.Count -ge 3 -and $meaningfulContext){$score+=1}

              if($originalFilename -and $mod.ModuleName -and [System.IO.Path]::GetFileName($originalFilename) -ne $mod.ModuleName -and $meaningfulContext){$score+=2}

              if($hash -and $knownCheatHashes.Contains($hash)){$score+=15}

              if($score -ge 4 -and $meaningfulContext){

                  $ev=@('Unexpected module loaded into Roblox process')

                  if($sig -eq 'NotSigned'){$ev+='Unsigned module'}
                  if($sig -eq 'NotSigned' -and $pathRisk -gt 0){$ev+='Unsigned external module loaded from a user-writable location; review required'}

                  if($publisher){$ev+="Publisher: $publisher"}

                  if($originalFilename -and $mod.ModuleName -and [System.IO.Path]::GetFileName($originalFilename) -ne $mod.ModuleName){$ev+='PE filename mismatch'}

                  if($pathRisk -gt 0){$ev+='Module from user-writable path'}
                  if($outsideRobloxPath -and $metadataMismatch){$ev+='External module path combined with PE original-filename mismatch'}

                  if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

                  if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}
                  if($binaryIndicators.Count -ge 2){$ev+="Binary API strings (weak static evidence; not proof of execution): $($binaryIndicators -join ', ')"}

                  if($hash -and $knownCheatHashes.Contains($hash)){$ev+='Known SHA256'}

                  Add-Result 'Roblox Injected Module' $mod.ModuleName $modPath "Process: $($rp.ProcessName) (PID $($rp.Id)) | Signature: $sig$(if($hash){" | SHA256: $hash"})" (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

                  $counts.RobloxModules++

              }

          }catch{}

      }

  }

  if($robloxProcs.Count -eq 0){Write-Host '      Roblox is not currently running' -ForegroundColor DarkGray}

}catch{}

Write-Host "      Matches: $($counts.RobloxModules)"

Write-Host '[5/13] Scheduled Tasks' -ForegroundColor Cyan

try{

  foreach($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)){

      $actions=@($task.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments) $($_.WorkingDirectory)"})

      $triggers=@($task.Triggers|ForEach-Object{"$($_.CimClass) $($_.AtLogOn) $($_.AtStartup) $($_.Enabled)"})

      $principal=if($task.Principal){"$($task.Principal.UserId) $($task.Principal.RunLevel) $($task.Principal.LogonType)"}else{''}

      $text="$($task.TaskName) $($task.TaskPath) $($actions -join ' ') $($triggers -join ' ') $principal"

      $matched=@(Get-MatchedKeywords $text)

      $behavior=@(Get-MatchedBehavior $text)

      $pathRisk=if(($actions -join ' ') -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\'){2}else{0}

      $score=Get-SuspicionScore -Name $task.TaskName -Path $task.TaskPath -ExtraText ($actions -join ' ')

      $score+=$pathRisk

      if($behavior.Count -ge 2){$score+=2}

      if($behavior.Count -ge 4){$score+=2}

      if(($actions -join ' ') -match '(?i)(^|[\\/])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?(?:\s|$)'){$score+=1}

      if(($actions -join ' ') -match '(?i)(-enc|-encodedcommand|frombase64string|downloadstring|downloadfile|http[s]?://)'){$score+=2}

      if($score -ge 3){

          $ev=@()

          if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

          if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

          if($pathRisk){$ev+='User-writable task target'}

          Add-Result 'Scheduled Task' $task.TaskName $task.TaskPath "Actions: $($actions -join ' | ')" (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

          $counts.Tasks++

      }

  }

}catch{}

Write-Host "      Matches: $($counts.Tasks)"

Write-Host '[6/13] Windows Services' -ForegroundColor Cyan

try{

  foreach($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)){

      $text="$($svc.Name) $($svc.DisplayName) $($svc.PathName)"

      $matched=@(Get-MatchedKeywords $text)

      $behavior=@(Get-MatchedBehavior $text)

      $path=[string]$svc.PathName

      $serviceImage=$path

      if($serviceImage -match '^\s*"([^"]+)"'){ $serviceImage=$Matches[1] } elseif($serviceImage -match '^\s*([^\s]+\.(?:exe|dll|sys))(?:\s|$)'){ $serviceImage=$Matches[1] }

      $score=Get-SuspicionScore -Name $svc.Name -Path $serviceImage -CommandLine $path -ExtraText $svc.DisplayName

      if($svc.StartMode -eq 'Auto' -and $serviceImage -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\'){$score+=3}

      if($behavior.Count -ge 2){$score+=2}

      if($behavior.Count -ge 4){$score+=2}

      if($matched.Count -or $serviceImage -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\'){

          $score+=1

      }

      if($score -ge 3){

          $ev=@()

          if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

          if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

          if($serviceImage -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\'){$ev+='Service binary in user-writable path'}

          Add-Result 'Windows Service' $svc.Name $serviceImage "State: $($svc.State) | StartMode: $($svc.StartMode)" (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

          $counts.Services++

      }

  }

}catch{}

Write-Host "      Matches: $($counts.Services)"

Write-Host '[7/13] Windows Prefetch' -ForegroundColor Cyan

$prefetch='C:\Windows\Prefetch'
$prefetchItemsProcessed=0

try{

  if(Test-Path $prefetch){

      foreach($f in Get-ChildItem $prefetch -Filter '*.pf' -File -ErrorAction SilentlyContinue|Where-Object{$_.LastWriteTime -gt (Get-Date).AddDays(-30)}){
          $prefetchItemsProcessed++
          if($prefetchItemsProcessed -gt $maxPrefetchItems){break}

          $matched=@(Get-MatchedKeywords $f.Name)

          if($matched.Count){

              $score=4

              $tier=Get-KeywordTier $matched

              if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}

              Add-Result 'Prefetch Artifact' $f.Name $f.FullName 'Recent execution-history artifact' (Get-SeverityFromScore $score) $score (Get-Confidence $score 'Execution artifact') ($matched -join ', ') 'Execution artifact; Recent Prefetch'

              $counts.Prefetch++

          }

      }

  }

}catch{}

Write-Host "      Matches: $($counts.Prefetch)"

Write-Host '[8/13] DNS cache' -ForegroundColor Cyan

try{

  foreach($entry in @(Get-DnsClientCache -ErrorAction SilentlyContinue)){

      $name=[string]$entry.Entry

      $matched=@(Get-MatchedKeywords $name)

      if($matched.Count){

          $score=2

          $tier=Get-KeywordTier $matched

          if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}

          Add-Result 'DNS Cache' $name 'DNS cache' "Type: $($entry.Type)" (Get-SeverityFromScore $score) $score (Get-Confidence $score 'DNS indicator') ($matched -join ', ') 'DNS keyword indicator'

          $counts.DNS++

      }

  }

}catch{}

Write-Host "      Matches: $($counts.DNS)"

Write-Host '[9/13] PowerShell profiles and history' -ForegroundColor Cyan

$profiles=@($PROFILE.CurrentUserCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.AllUsersAllHosts)|Select-Object -Unique

foreach($profilePath in $profiles){

  try{

      if(Test-Path $profilePath){

          $content=Get-Content $profilePath -Raw

          $matched=@(Get-MatchedKeywords $content)

          $behavior=@(Get-MatchedBehavior $content)

          if($matched.Count -or $behavior.Count -ge 2){

              $score=2

              $tier=Get-KeywordTier $matched

              if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}

              if($behavior.Count -ge 2){$score+=2}

              Add-Result 'PowerShell Profile' (Split-Path $profilePath -Leaf) $profilePath 'Indicator found in profile' (Get-SeverityFromScore $score) $score (Get-Confidence $score 'Profile indicator') ($matched -join ', ') "PowerShell profile indicator$(if($behavior.Count){"; Behavior: $($behavior -join ', ')"} )"

              $counts.Profiles++

          }

      }

  }catch{}

}

foreach($hist in @("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\VisualStudio_code_history.txt")){
  try{
      if(Test-Path $hist){
          $historyHits=0
          foreach($line in Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue){
              if($historyHits -ge 200 -or (Get-Date) -gt $scanDeadline){break}
              $text=[string]$line
              if([string]::IsNullOrWhiteSpace($text)){continue}
              $matched=@(Get-MatchedKeywords $text)
              $behavior=@(Get-MatchedBehavior $text)
              if($matched.Count -eq 0 -and $behavior.Count -lt 2){continue}
              $score=2
              $tier=Get-KeywordTier $matched
              if($tier -eq 'High'){$score+=2}elseif($tier -eq 'Medium'){$score+=1}
              if($behavior.Count -ge 2){$score+=2}
              Add-Result 'PowerShell History' (Split-Path $hist -Leaf) $hist 'Indicator found in command history' (Get-SeverityFromScore $score) $score (Get-Confidence $score 'History indicator') ($matched -join ', ') "PowerShell command-history indicator$(if($behavior.Count){"; Behavior: $($behavior -join ', ')"})"
              $counts.Profiles++
              $historyHits++
          }
      }
  }catch{}
}

Write-Host "      Matches: $($counts.Profiles)"

Write-Host '[10/13] Windows Defender history' -ForegroundColor Cyan

try{

  foreach($threat in @(Get-MpThreatDetection -ErrorAction SilentlyContinue)){

      $name=[string]$threat.ThreatName

      $resources=[string]$threat.Resources

      $sev=if($name -match '(?i)HackTool|Trojan|Backdoor|Malware|Ransom|Stealer|Cheat|Executor|Exploit|Inject'){'HIGH'}else{'MEDIUM'}

      $score=if($sev -eq 'HIGH'){15}else{8}

      Add-Result 'Defender Detection' $name $resources "Detected: $($threat.InitialDetectionTime)" $sev $score 'Very High' '' 'Windows Defender detection'

      $counts.Defender++

  }

}catch{}

Write-Host "      Detections in history: $($counts.Defender)"

Write-Host '[11/13] Windows event logs' -ForegroundColor Cyan

$eventResultConsumed=$false
$eventScanCompleted=$true

if($eventHandle.IsCompleted){

  try{

      $eventResult=@($eventPS.EndInvoke($eventHandle))

      $eventResultConsumed=$true

      $eventResultObj=$eventResult | Select-Object -First 1

      $eventHits=if($eventResultObj -and $eventResultObj.PSObject.Properties['Findings']){@($eventResultObj.Findings)}else{@($eventResult)}

      if($eventResultObj -and $eventResultObj.PSObject.Properties['EventsChecked']){$script:scanStats.EventsChecked=[int]$eventResultObj.EventsChecked}

      foreach($eh in $eventHits){

          Add-Result 'Event Log' $eh.Name $eh.Path $eh.Details $eh.Severity $eh.Score $eh.Confidence $eh.Keyword $eh.Evidence

          $counts.EventLogs++

      }

      # The completed event-log result is also checked in step 13. Clear the
      # already-consumed batch here so it is not added/count­ed a second time.
      $eventHits=@()

  }catch{

      # EndInvoke can only be consumed once. Mark it consumed even if the
      # background pipeline completed with an exception.
      $eventResultConsumed=$true
      $eventScanCompleted=$false

  }

}else{

  Write-Host '      Event scan still running; results will be collected later' -ForegroundColor DarkGray

}

Write-Host "      Matches: $($counts.EventLogs)"

Write-Host '[12/13] Command execution artifacts' -ForegroundColor Cyan

try{

  $mru='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'

  if(Test-Path $mru){

      $props=Get-ItemProperty $mru -ErrorAction SilentlyContinue

      foreach($p in $props.PSObject.Properties){

          if($p.Name -like 'PS*'){continue}

          $text="$($p.Name) $($p.Value)"

          $matched=@(Get-MatchedKeywords $text)

          $behavior=@(Get-MatchedBehavior $text)

          $score=0

          if($matched.Count){$score=2;$tier=Get-KeywordTier $matched;if($tier -eq 'High'){$score+=3}elseif($tier -eq 'Medium'){$score+=1}}

          if($behavior.Count -ge 2){$score+=2}

          if($p.Value -match '(?i)\\(Temp|AppData|Downloads|Desktop)\\' -and $p.Value -match '(?i)\.(exe|dll|bat|cmd|ps1|vbs|js)'){$score+=2}

          if($score -ge 3){

              $ev=@('Command execution artifact')

              if($matched.Count){$ev+="Keyword: $($matched -join ', ')"}

              if($behavior.Count){$ev+="Behavior: $($behavior -join ', ')"}

              Add-Result 'RunMRU' $p.Name $mru ([string]$p.Value) (Get-SeverityFromScore $score) $score (Get-Confidence $score ($ev -join '; ')) ($matched -join ', ') ($ev -join '; ')

              $counts.RunMRU++

          }

      }

  }

}catch{}

Write-Host "      Matches: $($counts.RunMRU)"

Write-Host '[13/13] Files, hashes, PE metadata and one-pass baseline' -ForegroundColor Cyan

$fileScanResult=$null

$fileCollected=$false

# Step 11 may already have consumed the event-log async result. Preserve those
# findings instead of clearing them, and never call EndInvoke() twice.

$eventCollected=[bool]$eventResultConsumed

if(-not $eventCollected){$eventHits=$null}

$lastStillScanningMessage=Get-Date

$stillScanningPrinted=$false

# Do not block on WaitOne() here. Both scans were started in the background
# before step 1, so step 13 polls them while keeping the console responsive.

# This is also where the user gets an explicit "still scanning" status.

while(-not ($fileCollected -and $eventCollected)){

  $now=Get-Date

  if(-not $fileCollected -and $fileHandle.IsCompleted){

      try{

          $fileScanResult=$filePS.EndInvoke($fileHandle)

      }catch{

          $fileScanResult=$null

      }

      $fileCollected=$true

      Write-Host '      file scan finished; collecting results...' -ForegroundColor DarkGray

  }

  if(-not $eventCollected -and $eventHandle.IsCompleted){

      try{

          $eventResult=@($eventPS.EndInvoke($eventHandle))

          $eventResultObj=$eventResult | Select-Object -First 1

          $eventHits=if($eventResultObj -and $eventResultObj.PSObject.Properties['Findings']){@($eventResultObj.Findings)}else{@($eventResult)}

          if($eventResultObj -and $eventResultObj.PSObject.Properties['EventsChecked']){$script:scanStats.EventsChecked=[int]$eventResultObj.EventsChecked}

      }catch{

          $eventHits=@()
          $eventScanCompleted=$false

      }

      $eventCollected=$true

      Write-Host '      event-log scan finished; collecting results...' -ForegroundColor DarkGray

  }

  if($fileCollected -and $eventCollected){break}

  if(($now-$lastStillScanningMessage).TotalSeconds -ge $monitorIntervalSeconds -or -not $stillScanningPrinted){

      $running=@()

      if(-not $fileCollected){$running+='file scan'}

      if(-not $eventCollected){$running+='event-log scan'}

      Write-Host "      still scanning: $($running -join ' + ')..." -ForegroundColor Yellow

      $lastStillScanningMessage=$now

      $stillScanningPrinted=$true

  }

  if($now -ge $scanDeadline){

      if(-not $fileCollected){

          try{$filePS.Stop()}catch{}

          $fileCollected=$true

          $fileScanResult=$null

          $scanStats.ScanTimedOut++
          Write-Host '      File scan exceeded deadline and was stopped safely.' -ForegroundColor Yellow

      }

      if(-not $eventCollected){

          try{$eventPS.Stop()}catch{}

          $eventCollected=$true

          $eventHits=@()

          $eventScanCompleted=$false
          $scanStats.ScanTimedOut++
          Write-Host '      Event scan exceeded deadline and was stopped safely.' -ForegroundColor Yellow

      }

      break

  }

  Start-Sleep -Milliseconds 500

}

if($fileScanResult){

  foreach($fh in @($fileScanResult.Findings)){

      Add-Result 'File' $fh.Name $fh.FullName $fh.Details $fh.Severity $fh.Score $fh.Confidence $fh.Keyword $fh.Evidence

      $counts.Files++

  }

}

if ($fileScanResult -and $fileScanResult.PSObject.Properties['EnumerationErrors']) {
  $scanStats.EnumerationErrors = [int]$fileScanResult.EnumerationErrors
}

Write-Host "      Matches: $($counts.Files)"

if($eventHits){

  foreach($eh in @($eventHits)){

      Add-Result 'Event Log' $eh.Name $eh.Path $eh.Details $eh.Severity $eh.Score $eh.Confidence $eh.Keyword $eh.Evidence

      $counts.EventLogs++

  }

}

Write-Host "      Event log matches: $($counts.EventLogs)"

Write-Host "      Background scans: file=$fileCollected, events=$eventCollected" -ForegroundColor DarkGray

try{$filePS.Dispose()}catch{}
try{$fileRS.Close()}catch{}
try{$fileRS.Dispose()}catch{}
try{$eventPS.Dispose()}catch{}
try{$eventRS.Close()}catch{}
try{$eventRS.Dispose()}catch{}

Write-Host ''

Write-Host '============================================================' -ForegroundColor Cyan

Write-Host '                     CORRELATION' -ForegroundColor Cyan

Write-Host '============================================================' -ForegroundColor Cyan

$processEvidence=@($results|Where-Object Type -eq 'Running Process')
$fileEvidence=@($results|Where-Object Type -eq 'File')

# Correlate exact executable paths in linear time. Do not search the whole
# command line, where an unrelated argument could mention another file path.
$processExecutablePaths=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($pr in $processEvidence){
  $pathMatch=[regex]::Match([string]$pr.Details,'(?im)^Path:\s*(.+?)\s+\|\s+Parent:')
  if(-not $pathMatch.Success){continue}
  try{$processPath=[System.IO.Path]::GetFullPath($pathMatch.Groups[1].Value).TrimEnd([char]92)}catch{$processPath=$pathMatch.Groups[1].Value.TrimEnd([char]92)}
  if($processPath){[void]$processExecutablePaths.Add($processPath)}
}
foreach($fr in $fileEvidence){
  if(-not $fr.Path -or $fr.Path.Length -lt 6){continue}
  try{$filePath=[System.IO.Path]::GetFullPath([string]$fr.Path).TrimEnd([char]92)}catch{$filePath=[string]$fr.Path.TrimEnd([char]92)}
  if($processExecutablePaths.Contains($filePath)){
    Add-TextEvidence -Target $fr -AddedEvidence 'Process/file correlation'
  }
}

# Cross-source confidence correlation is restricted to absolute, file-like paths.
# Registry keys, PIDs, DNS labels, log names and generic placeholders are excluded.
function Test-ConcreteFilePath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  return ($Path -match '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\).+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|lnk|lua|luau|scr|com|msi|pf)$')
}

$filePathGroups=@($results | Where-Object { Test-ConcreteFilePath ([string]$_.Path) } | Group-Object {
  try { [System.IO.Path]::GetFullPath([string]$_.Path).TrimEnd([char]92).ToLowerInvariant() }
  catch { ([string]$_.Path).TrimEnd([char]92).ToLowerInvariant() }
})

foreach($g in $filePathGroups){
  $types=@($g.Group | Select-Object -ExpandProperty Type -Unique)
  if($types.Count -lt 2){continue}

  foreach($r in $g.Group){
    Add-TextEvidence -Target $r -AddedEvidence ('Independent evidence: ' + ($types -join ', '))
    if($r.Score -ge 12 -and $r.Confidence -in @('Low','Medium') -and
       $r.RawEvidence -match '(?i)Process/file correlation|Independent evidence:' -and
       $r.RawEvidence -match '(?i)Behavior|SHA256|Defender|inject|hook|executor|exploit|suspicious'){
      $r.Confidence='High'
    }
  }
}

# Historical artifacts often contain only a filename (e.g. Prefetch), not a
# reliable original path. Basename-only matching is ambiguous and is not used
# to upgrade confidence or append corroborating evidence.

Write-Host ''

Write-Host '============================================================' -ForegroundColor Cyan

Write-Host '                 FILE INTEGRITY / BASELINE' -ForegroundColor Cyan

Write-Host '============================================================' -ForegroundColor Cyan

$currentBaseline=@{}

if($fileScanResult -and $fileScanResult.Baseline){

  foreach($identity in @($fileScanResult.Baseline)){

      if($identity.Path){$currentBaseline[[string]$identity.Path]=$identity}

  }

}

$fileScanCompleted = $fileScanResult -and ($fileScanResult.Completed -eq $true)

if($baselineLoadFailed){

  Write-Host '      Baseline comparison skipped: the existing baseline could not be validated.' -ForegroundColor Yellow

}elseif($baselineEntries.Count -gt 0 -and $fileScanCompleted){

  $before=$results.Count

  Test-FileIntegrity $baselineEntries $currentBaseline

  $counts.Integrity=$results.Count-$before

  Write-Host "      Integrity findings: $($counts.Integrity)"

 }elseif($baselineEntries.Count -gt 0){

  Write-Host '      Baseline comparison skipped: file inventory was incomplete.' -ForegroundColor Yellow

}else{

  Write-Host '      No previous baseline found; creating initial baseline.' -ForegroundColor Yellow

}

if($currentBaseline.Count -gt 0 -and $fileScanCompleted -and -not $baselineLoadFailed){

  if(Save-FileBaseline $currentBaseline $baselinePath){

      $baselineUpdated=$true

      Write-Host "      Baseline entries: $($currentBaseline.Count)" -ForegroundColor DarkGray

      Write-Host "      Baseline: $baselinePath" -ForegroundColor DarkGray

  }else{

      Write-Host '      Baseline could not be saved.' -ForegroundColor Yellow

  }

}elseif($baselineLoadFailed){

  Write-Host '      Existing baseline was not overwritten because it could not be read.' -ForegroundColor Yellow

}elseif(-not $fileScanCompleted){

  Write-Host '      File scan hit the deadline or had enumeration errors; baseline was not overwritten with partial data.' -ForegroundColor Yellow

}else{

  Write-Host '      No baseline data available to save.' -ForegroundColor Yellow

}

Invoke-HistoricalForensics

if ((Get-Date) -ge $scanDeadline) {
  $scanStats.ScanTimedOut++
}
$script:scanComplete = [bool]($fileScanCompleted -and $eventScanCompleted -and $scanStats.ScanTimedOut -eq 0 -and $scanStats.EnumerationErrors -eq 0 -and $scanStats.FileErrors -eq 0 -and $scanStats.WatcherErrors -eq 0 -and $scanStats.ProcessErrors -eq 0)

function Write-ForensicReports {

  param([object[]]$Findings)

  $txtWritten=$false;$jsonWritten=$false;$directoryReady=$true
  try{if(-not(Test-Path -LiteralPath $reportDirectory)){New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop|Out-Null}}catch{Write-Warning ('Could not create report directory: '+$_.Exception.Message);$directoryReady=$false}

  $stamp=(Get-Date).ToString('yyyy-MM-dd_HH-mm-ss-fff') + '_' + [guid]::NewGuid().ToString('N').Substring(0,8)

  $txtPath=Join-Path $reportDirectory "ForensicScanner8.8_Report_$stamp.txt"

  $jsonPath=Join-Path $reportDirectory "ForensicScanner8.8_Report_$stamp.json"

  $duration=[Math]::Round(((Get-Date)-$scriptStart).TotalSeconds,1)

  $filesScanned=if($fileScanResult -and $fileScanResult.PSObject.Properties['FilesVisited']){[int]$fileScanResult.FilesVisited}else{0}
  $filesAnalyzed=if($fileScanResult -and $fileScanResult.PSObject.Properties['FilesAnalyzed']){[int]$fileScanResult.FilesAnalyzed}else{0}

  $high=@($Findings|Where-Object Severity -eq 'HIGH').Count

  $medium=@($Findings|Where-Object Severity -eq 'MEDIUM').Count

  $low=@($Findings|Where-Object Severity -eq 'LOW').Count

  $info=@($Findings|Where-Object Severity -eq 'INFO').Count

  $baseStatus=if(@($Findings|Where-Object{($_.Severity -eq 'HIGH') -and ($_.Confidence -in @('High','Very High'))}).Count -gt 0){'HIGH CONFIDENCE DETECTION'}elseif(@($Findings|Where-Object{($_.Severity -in @('HIGH','MEDIUM')) -and ($_.Confidence -in @('Medium','High','Very High'))}).Count -gt 0){'SUSPICIOUS ACTIVITY'}elseif(@($Findings|Where-Object Severity -in @('LOW','INFO')).Count -gt 0){'LOW-CONFIDENCE INDICATORS'}else{'NO HIGH-CONFIDENCE DETECTIONS'}
  $status=if(-not $script:scanComplete){'PARTIAL SCAN - '+$baseStatus}else{$baseStatus}

  try{

      if(-not $directoryReady){throw 'Report directory is unavailable.'}
      $lines=[System.Collections.Generic.List[string]]::new()

      [void]$lines.Add('FORENSIC SCANNER 8.8 REPORT');[void]$lines.Add(('='*64));[void]$lines.Add("Status: $status");[void]$lines.Add("Scan complete: $script:scanComplete");[void]$lines.Add("Started UTC: $scanStartedUtc");[void]$lines.Add("Completed UTC: $((Get-Date).ToUniversalTime().ToString('o'))");[void]$lines.Add("Duration: ${duration}s");[void]$lines.Add('')

      [void]$lines.Add('EXECUTIVE SUMMARY');[void]$lines.Add(('='*64));[void]$lines.Add("Findings: $($Findings.Count)");[void]$lines.Add("High: $high | Medium: $medium | Low: $low | Info: $info")
      [void]$lines.Add("Actionable findings: $(@($Findings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') -or ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High')) }).Count)")
      [void]$lines.Add('Raw/full evidence is retained in the JSON report; this text report is intentionally concise.');[void]$lines.Add('Baseline comparisons use path, size, timestamps, and SHA256 when available; moves are correlated by matching SHA256.');[void]$lines.Add("Files visited: $filesScanned");[void]$lines.Add("Eligible files analyzed: $filesAnalyzed");[void]$lines.Add("Processes checked: $($counts.Processes)");[void]$lines.Add("Historical artifacts: $($counts.Historical)");[void]$lines.Add("Recycle Bin findings: $($counts.RecycleBin)");[void]$lines.Add("Cache findings: $($counts.Cache)");[void]$lines.Add('')

      if(@($Findings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') -or ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High')) }).Count -eq 0){[void]$lines.Add('No actionable findings were detected. Lower-confidence/info evidence may still be present in JSON.')}

      else{

          $n=1

          $sortedFindings=@($Findings|Sort-Object @{Expression='Score';Descending=$true},Severity,Type,Name)

          $listed=@($sortedFindings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') -or ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High')) } | Select-Object -First $maxReportListFindings)

          foreach($r in $listed){
              [void]$lines.Add("[$n] [$($r.Severity)] $($r.Name) | Confidence=$($r.Confidence) | Score=$($r.Score)")
              if($r.Path){[void]$lines.Add("Path: $(Get-DisplayFindingPath ([string]$r.Path) 170)")}
              if($r.Evidence){[void]$lines.Add("Why: $(Get-ConciseEvidence ([string]$r.Evidence) 350)")}
              if($r.Details){[void]$lines.Add("Details: $(Get-ConciseEvidence ([string]$r.Details) 300)")}
              if($r.Sources){[void]$lines.Add("Sources: $($r.Sources -join ', ')")}
              [void]$lines.Add('')
              $n++
          }

          $totalActionableInReport=@($sortedFindings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') -or ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High')) }).Count
          $hiddenInReport=[Math]::Max(0,$totalActionableInReport-$listed.Count)

          if($hiddenInReport -gt 0){[void]$lines.Add("... $hiddenInReport additional lower-priority findings omitted from this text report; see the JSON report for the full list.");[void]$lines.Add('')}

      }

      [void]$lines.Add('SCAN STATISTICS');[void]$lines.Add(('='*64));foreach($k in @('Registry','Startup','Files','Processes','RobloxModules','Tasks','Services','Prefetch','DNS','Profiles','Defender','EventLogs','RunMRU','Integrity','Historical','RecycleBin','Cache')){[void]$lines.Add("{0}: {1}" -f $k,$counts[$k])};[void]$lines.Add("Events checked: $($scanStats.EventsChecked)");[void]$lines.Add("Errors: Files=$($scanStats.FileErrors) | Enumeration=$($scanStats.EnumerationErrors) | Watchers=$($scanStats.WatcherErrors) | Processes=$($scanStats.ProcessErrors) | Timeouts=$($scanStats.ScanTimedOut)")

      [System.IO.File]::WriteAllLines($txtPath,$lines,(New-Object System.Text.UTF8Encoding($false)))
      $txtWritten=$true

  }catch{Write-Warning ('TXT report write failed: '+$_.Exception.Message)}

  try{

      if(-not $directoryReady){throw 'Report directory is unavailable.'}
      $doc=[PSCustomObject]@{Version='8.8';Status=$status;ScanComplete=[bool]$script:scanComplete;SuppressedFindings=$script:suppressedFindings;StartedUtc=$scanStartedUtc.ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o');DurationSeconds=$duration;Summary=[PSCustomObject]@{Total=$Findings.Count;High=$high;Medium=$medium;Low=$low;Info=$info};ScanMetrics=[PSCustomObject]@{FilesVisited=$filesScanned;EligibleFilesAnalyzed=$filesAnalyzed;FileDetections=$counts.Files;ProcessesChecked=$counts.Processes;EventsChecked=$scanStats.EventsChecked;HistoricalArtifacts=$counts.Historical};Counts=$counts;Errors=$scanStats;Findings=@($Findings|Sort-Object @{Expression='Score';Descending=$true})}

      [System.IO.File]::WriteAllText($jsonPath,($doc|ConvertTo-Json -Depth 8),(New-Object System.Text.UTF8Encoding($false)))
      $jsonWritten=$true

  }catch{Write-Warning ('JSON report write failed: '+$_.Exception.Message)}

  if(-not $txtWritten){$txtPath=$null};if(-not $jsonWritten){$jsonPath=$null}
  [PSCustomObject]@{Txt=$txtPath;Json=$jsonPath;TxtWritten=$txtWritten;JsonWritten=$jsonWritten;Status=$status;High=$high;Medium=$medium;Low=$low;Info=$info;Duration=$duration}

}

$finalFindings=@($results)

$confidenceRank=@{'Low'=1;'Medium'=2;'High'=3;'Very High'=4}
foreach($r in $finalFindings){
  $evidence = if($r.PSObject.Properties['RawEvidence'] -and -not [string]::IsNullOrWhiteSpace([string]$r.RawEvidence)){[string]$r.RawEvidence}else{[string]$r.Evidence}
  $calculated = Get-Confidence ([int]$r.Score) $evidence
  $existing = if($r.PSObject.Properties['Confidence']) {[string]$r.Confidence}else{'Low'}

  $preserveVeryHigh = ($existing -eq 'Very High' -and $evidence -match '(?i)Known SHA256|Windows Defender detection|Windows Defender historical detection')
  $preserveCorrelationHigh = ($existing -eq 'High' -and [int]$r.Score -ge 10 -and $evidence -match '(?i)Process/file correlation|Independent evidence:')

  if($preserveVeryHigh -or $preserveCorrelationHigh){
      $r.Confidence = $existing
  }else{
      $r.Confidence = $calculated
  }

  $r.Severity = Get-SeverityFromScore ([int]$r.Score)
}

$report=Write-ForensicReports $finalFindings

$high=$report.High;$medium=$report.Medium;$low=$report.Low;$info=$report.Info

Write-Host ''

$statusColor=if($high -gt 0){'Red'}elseif($medium -gt 0){'Yellow'}elseif($low -gt 0){'DarkYellow'}else{'Green'}

$filesScannedFinal=if($fileScanResult -and $fileScanResult.PSObject.Properties['FilesVisited']){[int]$fileScanResult.FilesVisited}else{0}
$filesAnalyzedFinal=if($fileScanResult -and $fileScanResult.PSObject.Properties['FilesAnalyzed']){[int]$fileScanResult.FilesAnalyzed}else{0}

$eventsChecked=$scanStats.EventsChecked

Write-Host ''

if($script:scanComplete){Write-Host '[+] Scan completed' -ForegroundColor $statusColor}else{Write-Host '[!] Scan completed with limitations; review the report and error counters.' -ForegroundColor Yellow}

Write-Host ''

Write-Host ("Files visited     : {0:N0}" -f $filesScannedFinal) -ForegroundColor Gray
Write-Host ("Eligible analyzed : {0:N0}" -f $filesAnalyzedFinal) -ForegroundColor Gray

Write-Host ("Processes checked : {0:N0}" -f $counts.Processes) -ForegroundColor Gray

Write-Host ("Events checked    : {0:N0}" -f $eventsChecked) -ForegroundColor Gray

$actionableFindings=@($finalFindings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') -or ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High')) })
$historicalFindings=@($finalFindings | Where-Object Type -match 'Historical')
Write-Host ("Findings          : {0:N0}" -f $finalFindings.Count) -ForegroundColor Gray
Write-Host ("Actionable        : {0:N0}" -f $actionableFindings.Count) -ForegroundColor Gray
Write-Host ("Historical        : {0:N0}" -f $historicalFindings.Count) -ForegroundColor Gray

Write-Host ''

Write-Host ("HIGH              : {0:N0}" -f $high) -ForegroundColor Gray

Write-Host ("MEDIUM            : {0:N0}" -f $medium) -ForegroundColor Gray

Write-Host ("LOW               : {0:N0}" -f $low) -ForegroundColor Gray

if($actionableFindings.Count -eq 0){

  Write-Host ''

  if($script:scanComplete){Write-Host 'No suspicious findings detected in the scanned data.' -ForegroundColor Green}else{Write-Host 'No actionable findings in the available data; the scan was incomplete, so this is not a clean result.' -ForegroundColor Yellow}

}else{

  Write-Host ''

  Write-Host 'Findings' -ForegroundColor Cyan

  Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray

  $n=1

  $displayFindings=@($finalFindings |
      Where-Object {
          $_.Severity -in @('HIGH','MEDIUM') -or
          ($_.Severity -eq 'LOW' -and $_.Confidence -in @('High','Very High'))
      } |
      Sort-Object @{Expression={switch($_.Severity){'HIGH'{3}'MEDIUM'{2}'LOW'{1}default{0}}};Descending=$true},
                   @{Expression='Score';Descending=$true},
                   @{Expression='Confidence';Descending=$true},
                   Name |
      Select-Object -First $maxConsoleFindings)

  foreach($r in $displayFindings){

      $c=switch($r.Severity){'HIGH'{'Red'}'MEDIUM'{'Yellow'}default{'DarkYellow'}}

      Write-Host "[$($r.Severity)] $($r.Name)" -ForegroundColor $c

      Write-Host "    Confidence : $($r.Confidence) | Score: $($r.Score)" -ForegroundColor Gray

      if($r.Path){$displayPath=Get-DisplayFindingPath ([string]$r.Path) 170; Write-Host "    Path       : $displayPath" -ForegroundColor Gray}

      if($r.Evidence){

          $ev=Get-ConciseEvidence ([string]$r.Evidence) 280
          Write-Host "    Why        : $ev" -ForegroundColor DarkCyan

      }

      if($r.Sources){Write-Host "    Sources    : $($r.Sources -join ', ')" -ForegroundColor DarkGray}

      Write-Host ''

      $n++

  }

  $hidden=[Math]::Max(0,$actionableFindings.Count-$displayFindings.Count)

  if($hidden -gt 0){

      Write-Host "... $hidden additional findings are in the full report." -ForegroundColor DarkGray

  }

}

if($script:suppressedFindings -gt 0){

  Write-Host ''

  Write-Host ("Safety limit: {0:N0} weaker duplicate/overflow findings were suppressed from memory/output." -f $script:suppressedFindings) -ForegroundColor DarkGray

}

Write-Host ''

if($report.Json -or $report.Txt){
  Write-Host 'Report files:' -ForegroundColor Cyan
  if($report.Json){Write-Host "  JSON: $($report.Json)" -ForegroundColor DarkGray}
  if($report.Txt){Write-Host "  TXT : $($report.Txt)" -ForegroundColor DarkGray}
}else{
  Write-Host 'Reports could not be written; check the warnings above and folder permissions.' -ForegroundColor Yellow
}

Write-Host ''

Write-Host ("Duration          : {0}s" -f $report.Duration) -ForegroundColor Gray

if(($scanStats.FileErrors + $scanStats.EnumerationErrors + $scanStats.WatcherErrors + $scanStats.ProcessErrors + $scanStats.ScanTimedOut) -gt 0){
  Write-Host ("Warnings/errors    : Files={0} | Enumeration={1} | Watchers={2} | Processes={3} | Timeouts={4}" -f $scanStats.FileErrors,$scanStats.EnumerationErrors,$scanStats.WatcherErrors,$scanStats.ProcessErrors,$scanStats.ScanTimedOut) -ForegroundColor Yellow
  Write-Host 'Some telemetry could not be read; this scan is not proof of a clean system.' -ForegroundColor DarkGray
}

Write-Host ''

if($Monitor){
  Write-Host 'Monitoring requested (-Monitor). Safety limits are enabled.' -ForegroundColor Yellow
  Write-Host 'Console status is rate-limited; monitoring work is bounded per cycle.' -ForegroundColor DarkGray
  Start-ContinuousMonitoring -IntervalSeconds $MonitorIntervalSeconds
}else{
  Write-Host 'Monitoring not started. Use -Monitor to enable continuous monitoring.' -ForegroundColor DarkGray
}