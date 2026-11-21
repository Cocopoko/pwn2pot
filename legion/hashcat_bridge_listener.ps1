# hashcat_bridge_listener.ps1
#
# Legion-side half of the coco2 hashcat bridge. Listens for WPA .22000
# hashes POSTed by the pwnagotchi plugin, then cracks each one with
# hashcat: a quick wordlist pass, a full wordlist pass, then a
# rules pass. Cracks land in cracked.log; everything is logged to
# listener.log. Runs at logon via the scheduled task install.ps1 makes.
#
# Defaults match a hashcat 6.2.6 folder in Downloads and the
# WPA-probable v2 wordlists in OneDrive\Desktop\Wordlist-V2.

param(
    [int]$Port = 8765,
    [string]$Token = '',
    [string]$HashcatDir  = "$env:USERPROFILE\Downloads\hashcat-6.2.6",
    [string]$WordlistDir = "$env:USERPROFILE\OneDrive\Desktop\Wordlist-V2",
    [string]$WorkDir     = "$env:USERPROFILE\hashcat-bridge"
)

$ErrorActionPreference = 'Continue'

$Inbox      = Join-Path $WorkDir 'inbox'
$Done       = Join-Path $WorkDir 'done'
$Pot        = Join-Path $WorkDir 'bridge.potfile'
$CrackedLog = Join-Path $WorkDir 'cracked.log'
$SeenFile   = Join-Path $WorkDir 'seen.txt'
$LogFile    = Join-Path $WorkDir 'listener.log'

foreach ($d in @($WorkDir, $Inbox, $Done)) {
    if (!(Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
foreach ($f in @($CrackedLog, $SeenFile, $LogFile)) {
    if (!(Test-Path $f)) { New-Item -ItemType File -Path $f -Force | Out-Null }
}

# Token falls back to the one install.ps1 generated.
if (!$Token) {
    $tokenPath = Join-Path $WorkDir 'token.txt'
    if (Test-Path $tokenPath) { $Token = (Get-Content $tokenPath -Raw).Trim() }
}

function Log($msg) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Invoke-CrackPasses($HashFile) {
    $hc = Join-Path $HashcatDir 'hashcat.exe'
    if (!(Test-Path $hc)) { Log "hashcat.exe not found in $HashcatDir"; return $null }
    $quick = Join-Path $WordlistDir 'Top204Thousand-WPA-probable-v2.txt'
    $full  = Join-Path $WordlistDir 'Top1pt2Million-WPA-probable-v2.txt'
    $rules = Join-Path $WordlistDir 'rule\rockyou-30000.rule'
    $passes = @(
        @{ List = $quick; Rules = $null  },
        @{ List = $full;  Rules = $null  },
        @{ List = $full;  Rules = $rules }
    )
    $prev = Get-Location
    Set-Location $HashcatDir
    try {
        foreach ($p in $passes) {
            if (!(Test-Path $p.List)) { Log "wordlist missing, skipping pass: $($p.List)"; continue }
            $hcArgs = @('-m', '22000', '-d', '1', '--quiet', '--session', 'bridge',
                        '--potfile-path', $Pot, $HashFile, $p.List)
            if ($p.Rules -and (Test-Path $p.Rules)) { $hcArgs += @('-r', $p.Rules) }
            Log "hashcat pass: $(Split-Path $p.List -Leaf)$(if ($p.Rules) { ' + rules' })"
            & $hc @hcArgs | Out-Null
            $shown = & $hc -m 22000 --show --potfile-path $Pot $HashFile 2>$null
            if ($shown) { return $shown }
        }
    } finally {
        Set-Location $prev
    }
    return $null
}

function Process-Inbox {
    foreach ($file in Get-ChildItem $Inbox -Filter *.22000) {
        Log "cracking $($file.Name)"
        $shown = Invoke-CrackPasses $file.FullName
        if ($shown) {
            foreach ($line in @($shown)) {
                Add-Content -Path $CrackedLog -Value ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $line)
                Log "CRACKED: $line"
            }
        } else {
            Log "all passes exhausted, no crack: $($file.Name)"
        }
        Move-Item $file.FullName (Join-Path $Done $file.Name) -Force
    }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()
Log "hashcat-bridge listener up on port $Port (hashcat: $HashcatDir)"

while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    try {
        $req = $ctx.Request
        if ($req.Url.AbsolutePath -ne '/submit') {
            $ctx.Response.StatusCode = 404
        } elseif ($Token -and $req.Headers['X-Bridge-Token'] -ne $Token) {
            $ctx.Response.StatusCode = 403
        } else {
            $reader = New-Object System.IO.StreamReader($req.InputStream)
            $body = $reader.ReadToEnd()
            $data = $body | ConvertFrom-Json
            $hash = [string]$data.hash
            if ($hash -notmatch '^WPA\*') {
                $ctx.Response.StatusCode = 400
            } elseif ((Get-Content $SeenFile) -contains $hash) {
                $ctx.Response.StatusCode = 200  # duplicate — already queued or cracked
            } else {
                Add-Content $SeenFile $hash
                $ssid = ([string]$data.ssid) -replace '[^\w\- ]', '_'
                if (!$ssid) { $ssid = 'unknown' }
                $name = '{0}_{1}.22000' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $ssid
                Set-Content -Path (Join-Path $Inbox $name) -Value $hash -Encoding ascii
                Log "received hash for '$ssid' -> $name"
                $ctx.Response.StatusCode = 200
            }
        }
    } catch {
        Log "request error: $_"
        try { $ctx.Response.StatusCode = 500 } catch {}
    } finally {
        try { $ctx.Response.Close() } catch {}
    }
    Process-Inbox
}
