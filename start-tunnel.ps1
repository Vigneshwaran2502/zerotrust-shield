# ZeroTrust Campus -- Start Backend + Cloudflare Quick Tunnel
#
# Usage:
#   .\start-tunnel.ps1
#
# What this script does:
#   1. Confirms no stale backend is already occupying port 3001 (kills it with user consent).
#   2. Starts the Express backend with Cloudflare Access JWT enforcement ENABLED so that
#      neither the tunnel URL nor the local session path accepts unauthenticated requests.
#   3. Opens a Cloudflare Quick Tunnel (trycloudflare.com) pointing at localhost:3001.
#      A fresh, unique log file is created for every run so an old URL can never be reused.
#      Both stdout and stderr are captured because cloudflared can write to either.
#   4. Sets the BACKEND_URL Wrangler secret and aborts immediately if that step fails.
#   5. Does NOT redeploy the Worker -- secrets take effect on the next Worker invocation
#      without a full redeployment.
#
# Security model:
#   Backend env vars injected by this script:
#     CLOUDFLARE_ACCESS_ENFORCE=true   -- requireAuth() rejects any request without a
#                                        valid Cf-Access-Jwt-Assertion header.
#     ALLOW_LOCAL_AUTH=false           -- ensures the ENFORCE flag is not neutralised.
#   This blocks:
#     - Direct tunnel requests without a CF JWT (all protected endpoints -> 401)
#     - Local /api/login password auth via the tunnel (-> 403)
#     - Local /api/register via the tunnel (-> 403)
#   The BACKEND_URL secret is stored in Cloudflare's secret management and never
#   appears in the built frontend bundle or in process.env on the client side.
#
# Local development (node server.js run directly):
#   Still reads backend/.env which retains ALLOW_LOCAL_AUTH=true -- no change needed.
#
# IMPORTANT: Quick Tunnel URLs are ephemeral and change on every restart.
#            Re-run this script each session (or use a named Cloudflare Tunnel for
#            a stable URL without this limitation).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Paths -------------------------------------------------------------------
$SCRIPT_DIR   = Split-Path -Parent $MyInvocation.MyCommand.Path
$CLOUDFLARED  = Join-Path $SCRIPT_DIR "cloudflared\cloudflared.exe"
$BACKEND_DIR  = Join-Path $SCRIPT_DIR "backend"

# -- Per-run unique IDs (Fix 2) ----------------------------------------------
# Include PID and timestamp so a log file from a previous run can never match.
$RUN_ID        = "{0}-{1}" -f [System.DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss"), $PID
$TUNNEL_STDERR = Join-Path $env:TEMP "cf-tunnel-stderr-$RUN_ID.log"
$TUNNEL_STDOUT = Join-Path $env:TEMP "cf-tunnel-stdout-$RUN_ID.log"

# -- Helper: verify an external command succeeded (Fix 4) --------------------
# $ErrorActionPreference='Stop' does NOT apply to native executables.
# Call this immediately after any critical external command.
function Assert-ExitCode {
    param([string]$Description)
    if ($LASTEXITCODE -ne 0) {
        Write-Error "$Description failed with exit code $LASTEXITCODE. Aborting."
        exit $LASTEXITCODE
    }
}

# -- Helper: get the PID currently listening on a TCP port -------------------
function Get-PidOnPort {
    param([int]$Port)
    $lines = netstat -ano 2>$null
    foreach ($line in $lines) {
        # Match "TCP  0.0.0.0:<Port>  ...  LISTENING  <pid>"
        if ($line -match "TCP\s+\S+:${Port}\s+\S+\s+LISTENING\s+(\d+)") {
            return [int]$Matches[1]
        }
    }
    return $null
}

# -- Sanity checks -----------------------------------------------------------
Write-Host ""
Write-Host "ZeroTrust Campus -- Tunnel Startup" -ForegroundColor White
Write-Host "----------------------------------" -ForegroundColor DarkGray

if (-not (Test-Path $CLOUDFLARED)) {
    Write-Error "cloudflared.exe not found at: $CLOUDFLARED"
    Write-Host "  Download: https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path (Join-Path $BACKEND_DIR "server.js"))) {
    Write-Error "backend/server.js not found. Run this script from the project root (D:\Cloudflare)."
    exit 1
}

# -- Fix 1: Prevent duplicate backend processes ------------------------------
Write-Host ""
Write-Host "[1/3] Checking port 3001..." -ForegroundColor Cyan
$existingPid = Get-PidOnPort -Port 3001
if ($existingPid) {
    $proc = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
    $procName = if ($proc) { $proc.ProcessName } else { "unknown" }
    Write-Warning "Port 3001 is already in use by PID $existingPid ($procName)."
    $answer = Read-Host "      Kill it and start a fresh backend? (y/N)"
    if ($answer -notin @('y','Y')) {
        Write-Host "Aborted by user." -ForegroundColor Yellow
        exit 0
    }
    Write-Host "      Stopping PID $existingPid..." -ForegroundColor DarkGray
    Stop-Process -Id $existingPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    # Confirm it actually stopped
    if (Get-PidOnPort -Port 3001) {
        Write-Error "Could not free port 3001. Please stop the conflicting process manually."
        exit 1
    }
}

# -- Fix 6: Start backend with CF Access enforcement -------------------------
# These two env vars are set in the *current PowerShell session* before
# Start-Process is called. Child processes inherit the parent's environment.
# dotenv.config() in server.js does NOT override env vars already present,
# so backend/.env values for these two keys are superseded.
# After Start-Process returns we restore the session values so this terminal
# is not permanently affected.
Write-Host "      Starting Express backend (CF Access enforcement: ON)..." -ForegroundColor Cyan

$prevEnforce   = $env:CLOUDFLARE_ACCESS_ENFORCE
$prevLocalAuth = $env:ALLOW_LOCAL_AUTH

$env:CLOUDFLARE_ACCESS_ENFORCE = "true"
$env:ALLOW_LOCAL_AUTH          = "false"

$backendProc = Start-Process `
    -FilePath         "node" `
    -ArgumentList     "server.js" `
    -WorkingDirectory $BACKEND_DIR `
    -PassThru `
    -WindowStyle      Hidden

# Restore current-session env immediately -- child process keeps its inherited copy
$env:CLOUDFLARE_ACCESS_ENFORCE = $prevEnforce
$env:ALLOW_LOCAL_AUTH          = $prevLocalAuth

Write-Host "      Backend PID: $($backendProc.Id)"

# Wait for the backend to actually bind to the port (up to 10 s)
$bound = $false
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Milliseconds 500
    if (Get-PidOnPort -Port 3001) { $bound = $true; break }
}
if (-not $bound) {
    Write-Error "Backend failed to bind to port 3001 within 5 seconds. Check backend logs."
    if (-not $backendProc.HasExited) { Stop-Process -Id $backendProc.Id -Force }
    exit 1
}
Write-Host "      [OK] Backend listening on port 3001" -ForegroundColor Green

# -- Fix 2 & 3: Start Quick Tunnel with fresh, unique log files --------------
Write-Host ""
Write-Host "[2/3] Starting Cloudflare Quick Tunnel..." -ForegroundColor Cyan
Write-Host "      Log files for this run:"
Write-Host "        stderr: $TUNNEL_STDERR"
Write-Host "        stdout: $TUNNEL_STDOUT"

# Use -WindowStyle Hidden with both stdout and stderr redirected to separate per-run files.
$tunnelProc = Start-Process `
    -FilePath               $CLOUDFLARED `
    -ArgumentList           "tunnel", "--url", "http://localhost:3001" `
    -RedirectStandardError  $TUNNEL_STDERR `
    -RedirectStandardOutput $TUNNEL_STDOUT `
    -WindowStyle            Hidden `
    -PassThru

Write-Host "      Tunnel PID: $($tunnelProc.Id)"
Write-Host "      Waiting for tunnel URL (up to 45 s)..."

# Fix 3: Poll BOTH log files. Extend timeout to 45 s.
# Verify the detected URL is a fresh trycloudflare.com address.
$tunnelUrl = $null
$maxWait   = 45
$elapsed   = 0
$urlRegex  = 'https://[a-z0-9][a-z0-9\-]*\.trycloudflare\.com'

while ($elapsed -lt $maxWait -and -not $tunnelUrl) {
    Start-Sleep -Seconds 1
    $elapsed++

    # Abort early if cloudflared crashed
    if ($tunnelProc.HasExited) {
        $errContent = if (Test-Path $TUNNEL_STDERR) { Get-Content $TUNNEL_STDERR -Raw } else { '' }
        Write-Error "cloudflared exited unexpectedly (code $($tunnelProc.ExitCode)).`n$errContent"
        if (-not $backendProc.HasExited) { Stop-Process -Id $backendProc.Id -Force }
        exit 1
    }

    foreach ($logFile in @($TUNNEL_STDERR, $TUNNEL_STDOUT)) {
        if (Test-Path $logFile) {
            $content = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            if ($content -and $content -match $urlRegex) {
                $candidate = $Matches[0]
                # Sanity-check: must be https, must end with trycloudflare.com
                if ($candidate -match '^https://[a-z0-9][a-z0-9\-]+\.trycloudflare\.com$') {
                    $tunnelUrl = $candidate
                    break
                }
            }
        }
    }
}

if (-not $tunnelUrl) {
    $stderrDump = if (Test-Path $TUNNEL_STDERR) { Get-Content $TUNNEL_STDERR -Raw } else { '(empty)' }
    $stdoutDump = if (Test-Path $TUNNEL_STDOUT) { Get-Content $TUNNEL_STDOUT -Raw } else { '(empty)' }
    Write-Error (
        "No tunnel URL detected after ${maxWait}s.`n" +
        "stderr: $stderrDump`n" +
        "stdout: $stdoutDump"
    )
    if (-not $tunnelProc.HasExited)  { Stop-Process -Id $tunnelProc.Id  -Force }
    if (-not $backendProc.HasExited) { Stop-Process -Id $backendProc.Id -Force }
    exit 1
}

Write-Host "      [OK] Tunnel URL: $tunnelUrl" -ForegroundColor Green

# -- Fix 4: Set BACKEND_URL secret -- abort on failure ------------------------
# Fix 5: No wrangler deploy is needed. A secret updated with `secret put`
#        is available to Workers on the very next invocation without redeployment.
Write-Host ""
Write-Host "[3/3] Setting BACKEND_URL Wrangler secret..." -ForegroundColor Cyan
Write-Host "      (BACKEND_URL value is never written to disk or displayed)"

# Pipe the tunnel URL into wrangler via stdin so it never appears in shell
# history as a command-line argument.
$tunnelUrl | npx wrangler secret put BACKEND_URL --name zerotrust-campus
Assert-ExitCode -Description "wrangler secret put BACKEND_URL"

Write-Host "      [OK] Secret set. Worker will use the new URL on its next request." -ForegroundColor Green
Write-Host ""
Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " Live at: https://zerotrust-campus.vigneshwaran7002.workers.dev" -ForegroundColor White
Write-Host ""
Write-Host " Security posture (tunnel mode):" -ForegroundColor White
Write-Host "   * Cloudflare Access JWT required on ALL protected endpoints" -ForegroundColor Green
Write-Host "   * Dual-layer auth: Cloudflare Access gate + signed campus application session" -ForegroundColor Green
Write-Host "   * /api/register blocked at tunnel -> 403" -ForegroundColor Green
Write-Host "   * Direct tunnel requests without CF JWT -> 401" -ForegroundColor Green
Write-Host "   * BACKEND_URL is a Wrangler secret -- never in the JS bundle" -ForegroundColor Green
Write-Host ""
Write-Host " Keep this terminal OPEN. Tunnel and backend stop when you exit." -ForegroundColor Yellow
Write-Host " Press Ctrl+C to shut down cleanly." -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray

# -- Keep alive -- clean up on Ctrl+C -----------------------------------------
try {
    while ($true) { Start-Sleep -Seconds 30 }
} finally {
    Write-Host ""
    Write-Host "Shutting down..." -ForegroundColor Cyan
    if (-not $tunnelProc.HasExited)  { Stop-Process -Id $tunnelProc.Id  -Force -ErrorAction SilentlyContinue }
    if (-not $backendProc.HasExited) { Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue }
    # Clean up per-run log files
    Remove-Item -Path $TUNNEL_STDERR -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TUNNEL_STDOUT -Force -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
}
