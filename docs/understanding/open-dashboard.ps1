# Open the Understand-Anything dashboard for threat-guard / Virodh AI.
#   powershell -ExecutionPolicy Bypass -File .\open-dashboard.ps1
# The graph lives in threat-guard\.ua\ (next to the source code, so the dashboard's code viewer can show files);
# this folder keeps a copy (knowledge-graph.json, code-lessons.json) plus ARCHITECTURE.md.
$project = "E:\PROJECTS\TIET SAturanalia\threat-guard"
$dashboard = "E:\PROJECTS\TIET SAturanalia\Understand-Anything\understand-anything-plugin\packages\dashboard"
if (-not (Test-Path "$project\.ua\knowledge-graph.json")) { Copy-Item "$PSScriptRoot\knowledge-graph.json", "$PSScriptRoot\code-lessons.json", "$PSScriptRoot\meta.json" "$project\.ua\" }
$env:GRAPH_DIR = $project
Set-Location $dashboard
Write-Host "Starting dashboard (opens in your browser; the URL with ?token= is printed below)..."
npx vite --host 127.0.0.1 --open
