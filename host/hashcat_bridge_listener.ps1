# hashcat_bridge_listener.ps1
#
# Host-side half of pwn2pot. Listens for WPA .22000
# hashes POSTed by the pwnagotchi plugin, then cracks each one with
# hashcat: a quick wordlist pass, a full wordlist pass, then a
# Singapore-list rules pass. Cracks land in cracked.log; everything is
# logged to listener.log. Runs at logon via the scheduled task
# install.ps1 makes.
#
# v1.2.0: submissions are ACKed (HTTP 200) the moment the hash is
# queued, and cracking runs in a background worker — the listener
# never sits blocked behind a long pass again. Files left in the
# inbox by a crash or reboot are resumed automatically at startup.
# Pass 3 uses the Singapore list (SOCradar SG-250) with the
# rockyou-30000 rules when the list is present in the wordlist
# folder, and falls back to the full list + rules when it is not.
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

# -------------------------------------------------------------------
# Background crack worker (own runspace, own copies of the helpers —
# runspaces share nothing but the queue passed in).
# -------------------------------------------------------------------
$script:Queue = New-Object System.Collections.Concurrent.ConcurrentQueue[string]

$workerScript = {
    param($Queue, $HashcatDir, $WordlistDir, $WorkDir)

    $Inbox      = Join-Path $WorkDir 'inbox'
    $Done       = Join-Path $WorkDir 'done'
    $Pot        = Join-Path $WorkDir 'bridge.potfile'
    $CrackedLog = Join-Path $WorkDir 'cracked.log'
    $LogFile    = Join-Path $WorkDir 'listener.log'

    function Log($msg) {
        $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
        Add-Content -Path $LogFile -Value $line
    }

    function Find-SgList {
        $names = @('srwordlist_sg_250.txt', 'sg250.txt', 'sg-250.txt', 'sg250-seed.txt')
        foreach ($n in $names) {
            $p = Join-Path $WordlistDir $n
            if (Test-Path $p) { return $p }
        }
        $hit = Get-ChildItem $WordlistDir -Filter '*sg*250*.txt' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
        return $null
    }

    function Invoke-CrackPasses($HashFile) {
        $hc = Join-Path $HashcatDir 'hashcat.exe'
        if (!(Test-Path $hc)) { Log "hashcat.exe not found in $HashcatDir"; return $null }
        $quick = Join-Path $WordlistDir 'Top204Thousand-WPA-probable-v2.txt'
        $full  = Join-Path $WordlistDir 'Top1pt2Million-WPA-probable-v2.txt'
        $rules = Join-Path $WordlistDir 'rule\rockyou-30000.rule'
        $sg    = Find-SgList
        if ($sg) {
            $third = $sg
        } else {
            Log "SG list not found in $WordlistDir - pass 3 falls back to the full list + rules"
            $third = $full
        }
        $passes = @(
            @{ List = $quick; Rules = $null  },
            @{ List = $full;  Rules = $null  },
            @{ List = $third; Rules = $rules }
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

    while ($true) {
        $file = $null
        if ($Queue.TryDequeue([ref]$file)) {
            try {
                if (Test-Path $file) {
                    $leaf = Split-Path $file -Leaf
                    Log "cracking $leaf"
                    $shown = Invoke-CrackPasses $file
                    if ($shown) {
                        foreach ($line in @($shown)) {
                            Add-Content -Path $CrackedLog -Value ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $line)
                            Log "CRACKED: $line"
                        }
                    } else {
                        Log "all passes exhausted, no crack: $leaf"
                    }
                    Move-Item $file (Join-Path $Done $leaf) -Force
                }
            } catch {
                Log "worker error: $_"
            }
        } else {
            Start-Sleep -Seconds 2
        }
    }
}

$workerRunspace = [runspacefactory]::CreateRunspace()
$workerRunspace.Open()
$workerPS = [powershell]::Create()
$workerPS.Runspace = $workerRunspace
[void]$workerPS.AddScript($workerScript).
    AddArgument($script:Queue).
    AddArgument($HashcatDir).
    AddArgument($WordlistDir).
    AddArgument($WorkDir)
$workerHandle = $workerPS.BeginInvoke()

# -------------------------------------------------------------------
# Accept loop — validate, dedupe, queue, ACK immediately.
# -------------------------------------------------------------------
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()
Log "hashcat-bridge listener up on port $Port (hashcat: $HashcatDir)"
Log "background crack worker running; submissions are ACKed on queue, never blocked by a running pass"

# Resume anything a previous run left in the inbox.
foreach ($f in Get-ChildItem $Inbox -Filter *.22000) {
    $script:Queue.Enqueue($f.FullName)
    Log "resumed queued file: $($f.Name)"
}

while ($listener.IsListening) {
    try {
        $ctx = $listener.GetContext()
    } catch {
        Start-Sleep -Seconds 1
        continue
    }
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
                $path = Join-Path $Inbox $name
                Set-Content -Path $path -Value $hash -Encoding ascii
                $script:Queue.Enqueue($path)
                Log "received hash for '$ssid' -> $name (queued)"
                $ctx.Response.StatusCode = 200
            }
        }
    } catch {
        Log "request error: $_"
        try { $ctx.Response.StatusCode = 500 } catch {}
    } finally {
        try { $ctx.Response.Close() } catch {}
    }
}
