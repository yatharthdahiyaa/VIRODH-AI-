# Start Virodh AI locally: Python inspection engine (:8000) + Node dashboard backend serving the React app (:3000).
#   powershell -ExecutionPolicy Bypass -File .\start_virodh.ps1
# Then open http://localhost:3000 — the first account you sign up becomes the admin.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not (Test-Path "$root\web\dist\index.html")) {
    Write-Host "Building the React app..."
    Push-Location "$root\web"; npm install --no-fund --no-audit; npx vite build; Pop-Location
}
if (-not (Test-Path "$root\server\node_modules")) { Push-Location "$root\server"; npm install --no-fund --no-audit; Pop-Location }
New-Item -ItemType Directory -Force "$root\logs" | Out-Null
$engine = Start-Process -PassThru -WindowStyle Minimized -FilePath "$root\.venv\Scripts\python.exe" `
    -ArgumentList "scripts\virodh_serve.py", "--workers", "2", "--port", "8000" -WorkingDirectory $root
Write-Host "Engine starting (pid $($engine.Id)); waiting until ready..."
for ($i = 0; $i -lt 90; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/readyz -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}
    Start-Sleep 2
}
$dash = Start-Process -PassThru -WindowStyle Minimized -FilePath "node" `
    -ArgumentList "--disable-warning=ExperimentalWarning", "src/index.js" -WorkingDirectory "$root\server"
Write-Host "Dashboard on http://localhost:3000 (pid $($dash.Id)). Engine on http://127.0.0.1:8000."
Write-Host "Stop both: Stop-Process -Id $($engine.Id),$($dash.Id)"
