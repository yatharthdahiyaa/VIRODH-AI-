# Open the Understand-Anything interactive dashboard for Virodh AI (Threat Guard).
#   powershell -ExecutionPolicy Bypass -File .\open-dashboard.ps1
#
# The knowledge graph lives in threat-guard\.ua\ (next to source code for interactive file viewing);
# docs/understanding/ keeps a persistent copy plus ARCHITECTURE.md and the call hierarchy.

$project = (Resolve-Path "$PSScriptRoot\..\..").Path
$candidateDashboards = @(
    "E:\PROJECTS\TIET SAturanalia\Understand-Anything\understand-anything-plugin\packages\dashboard",
    "$env:USERPROFILE\.understand-anything\repo\understand-anything-plugin\packages\dashboard"
)

$dashboard = $candidateDashboards | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $dashboard) {
    Write-Error "Understand-Anything dashboard package not found. Ensure Understand-Anything is cloned."
    exit 1
}

# Sync knowledge graph to .ua if not present
if (-not (Test-Path "$project\.ua\knowledge-graph.json")) {
    New-Item -ItemType Directory -Force -Path "$project\.ua" | Out-Null
    Copy-Item "$PSScriptRoot\knowledge-graph.json", "$PSScriptRoot\code-lessons.json", "$PSScriptRoot\meta.json" "$project\.ua\" -Force
}

$env:GRAPH_DIR = $project
$env:UNDERSTAND_ACCESS_TOKEN = "virodh-understanding-token"

Set-Location $dashboard
Write-Host "`n🚀 Starting Virodh AI Interactive Architecture Dashboard..." -ForegroundColor Cyan
Write-Host "🔑 URL: http://127.0.0.1:5174/?token=virodh-understanding-token`n" -ForegroundColor Green

npx vite --host 127.0.0.1 --port 5174 --open
