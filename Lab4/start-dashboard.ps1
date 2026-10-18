param([switch]$RefreshReports)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
        throw 'Create the Python environment first; see the README setup instructions.'
    }
    if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
        throw 'Install Node.js 22.12 or newer, then reopen PowerShell.'
    }
    $needsPacketStream = -not (Test-Path -LiteralPath 'frontend/public/reports/index.json')
    if (-not $needsPacketStream) {
        $captureIndex = Get-Content -LiteralPath 'frontend/public/reports/index.json' -Raw | ConvertFrom-Json
        $needsPacketStream = @($captureIndex | Where-Object { -not $_.packet_stream -or -not $_.packet_ports -or -not $_.packet_detections }).Count -gt 0
    }
    if ($RefreshReports -or $needsPacketStream) {
        & .venv/Scripts/python.exe dashboard.py data/test
        if ($LASTEXITCODE -ne 0) { throw 'Report export failed. Generate data/test first, or check the capture files.' }
    }
    if (-not (Test-Path -LiteralPath 'frontend/node_modules')) {
        & npm.cmd --prefix frontend ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    }
    & npm.cmd --prefix frontend run dev -- --open
} finally {
    Pop-Location
}
