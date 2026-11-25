# api_smoke.ps1 - checks a RUNNING detector.exe through its HTTP API.
# 1. In one PowerShell window:   .\run.bat
# 2. In a second window:         powershell -ExecutionPolicy Bypass -File tests\api_smoke.ps1
#    (add  -Port 8081  if detector.exe printed a different port)
# Works with Windows PowerShell 5.1 and PowerShell 7. Changes nothing on the PC.
param([int]$Port = 8080)

$base = "http://localhost:$Port"
$passed = 0; $failed = 0
function Check($name, $condition) {
    if ($condition) { Write-Host "  PASS  $name" -ForegroundColor Green; $script:passed++ }
    else            { Write-Host "  FAIL  $name" -ForegroundColor Red;   $script:failed++ }
}
function Post($path, $form) {
    # Invoke-RestMethod sends a hashtable as form data (a=1&b=2), like the dashboard.
    try { return Invoke-RestMethod -Method Post -Uri "$base$path" -Body $form }
    catch { return $null }
}
function State { return Invoke-RestMethod -Uri "$base/api/state" }

try { $s = State } catch {
    Write-Host "Cannot reach $base. Start detector.exe first (.\run.bat)." -ForegroundColor Red
    exit 1
}
Check "GET /api/state answers" ($null -ne $s.mode)

$r = Post "/api/simulate" @{ type = "fast"; attempts = 40; ips = 1; username = "admin"; seed = 3 }
Check "fast attack simulation starts" ($r.ok -eq $true)
$null = Post "/api/speed" @{ speed = 60 }
Start-Sleep -Seconds 4
$s = State
Check "events are being processed" ($s.progress.processed -gt 0)
$fast = $s.categories | Where-Object { $_.name -eq "Fast brute-force" }
Check "attacker classified as fast brute-force" ($fast.ips -ge 1)
Check "at least one ban was started" ($s.counters.total_bans -ge 1)

if ($s.blocked.Count -gt 0) {
    $ip = $s.blocked[0].ip
    $r = Post "/api/unblock" @{ ip = $ip }
    Check "manual unblock of $ip" ($r.ok -eq $true)
}

$r = Post "/api/settings" @{ short = 4; score = 55 }
$s = State
Check "settings change is applied" ($s.settings.score_threshold -eq 55)
$r = Post "/api/settings/undo" @{}
$s = State
Check "undo restores the old settings" ($s.settings.score_threshold -eq 60)

$r = Post "/api/simulate" @{ type = "evil" }
Check "invalid request is refused" ($null -eq $r)

$r = Post "/api/load_sample" @{}
Check "sample log loads (2 malformed lines skipped)" ($r.ok -eq $true -and $r.malformed -eq 2)

Write-Host "  ...running a small evaluation (a few seconds)"
$r = Post "/api/evaluate" @{ seeds = 1; events = 20000 }
Check "evaluation returns real results" ($r.ok -eq $true -and $r.evaluation.types.Count -eq 4)

$page = Invoke-WebRequest -Uri "$base/" -UseBasicParsing
Check "dashboard page is served" ($page.StatusCode -eq 200 -and $page.Content -match "Login Guard")

Write-Host ""
Write-Host "$passed passed, $failed failed"
if ($failed -gt 0) { exit 1 }
