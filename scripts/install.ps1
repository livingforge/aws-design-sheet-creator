param(
    [switch]$Llm,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$packageRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $packageRoot ".venv\Scripts\python.exe"

& $Python -m venv (Join-Path $packageRoot ".venv")
if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }

$packageSpec = if ($Llm) { "${packageRoot}[llm]" } else { $packageRoot }
& $venvPython -m pip install -e $packageSpec
if ($LASTEXITCODE -ne 0) { throw "Package installation failed." }

Write-Host "Installed in $packageRoot"
Write-Host "Run: $packageRoot\.venv\Scripts\aws-design-run.exe --help"
