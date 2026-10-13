param(
    [switch]$Llm,
    [switch]$Tests,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$packageRoot = Split-Path -Parent $PSScriptRoot
$venvDirectory = Join-Path $packageRoot ".venv"
$venvPython = Join-Path $venvDirectory "Scripts\python.exe"
& $Python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) and sys.version_info[:3] != (3, 14, 1) else 1)"
if ($LASTEXITCODE -ne 0) { throw "The locked release requires Python >=3.12, excluding 3.14.1." }
if (Test-Path -LiteralPath $venvDirectory) {
    throw "An environment already exists. Use a fresh skill copy; this installer does not delete environments."
}
& $Python -m venv $venvDirectory
if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }
$packageSpec = if ($Llm) { "${packageRoot}[llm]" } else { $packageRoot }
$constraints = Join-Path $packageRoot "requirements.lock"
& $venvPython -m pip --isolated install --index-url https://pypi.org/simple --constraint $constraints -e $packageSpec
if ($LASTEXITCODE -ne 0) { throw "Package installation failed." }
if ($Tests) {
    & $venvPython -m pip --isolated install --index-url https://pypi.org/simple --constraint $constraints pytest
    if ($LASTEXITCODE -ne 0) { throw "Test dependency installation failed." }
}
& $venvPython -m aws_design_sheet.schema_bootstrap
if ($LASTEXITCODE -ne 0) { throw "Schema setup failed; the environment and failed attempt are preserved. Retry with python -m aws_design_sheet.schema_bootstrap." }
Write-Host "Installed in $packageRoot"
Write-Host "Run: $venvPython -m aws_design_sheet.document_cli --help"
