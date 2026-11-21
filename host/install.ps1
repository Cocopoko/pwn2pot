# install.ps1 — run ONCE, as Administrator, from this folder.
#
# Generates the shared bridge token, saves it to
# %USERPROFILE%\hashcat-bridge\token.txt, opens the firewall ONLY to
# the pwnagotchi (10.0.0.2), and registers a logon scheduled task that
# keeps the listener running. Prints the token at the end — that token
# goes into the pwnagotchi config (see config.example.toml).

param([string]$Token = '')

$ErrorActionPreference = 'Stop'
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkDir = "$env:USERPROFILE\hashcat-bridge"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

if (!$Token) {
    $Token = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
}
Set-Content -Path (Join-Path $WorkDir 'token.txt') -Value $Token -Encoding ascii

# Firewall: only the pwnagotchi may reach the listener.
Get-NetFirewallRule -DisplayName 'pwn2pot' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'pwn2pot' -Direction Inbound `
    -Protocol TCP -LocalPort 8765 -RemoteAddress 10.0.0.2 `
    -Action Allow -Profile Any | Out-Null

# Let HttpListener bind without running as a service.
netsh http add urlacl url=http://+:8765/ user=Everyone | Out-Null

# Listener at every logon.
$listenerPath = Join-Path $Here 'hashcat_bridge_listener.ps1'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$listenerPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'hashcat-bridge' -Action $action -Trigger $trigger -Force | Out-Null
Start-ScheduledTask -TaskName 'hashcat-bridge'

Write-Host ''
Write-Host 'hashcat-bridge installed and running.'
Write-Host "Token (paste into the pwnagotchi config): $Token"
