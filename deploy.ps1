param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $DeployArgs
)

$ErrorActionPreference = "Stop"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python 3 is required. Install Python 3 and rerun this script."
}

$venv = Join-Path $PSScriptRoot ".deploy-venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "[mail-control] creating local deployment environment"
    & $python.Source -m venv $venv
    if ($LASTEXITCODE -ne 0) {
        throw "failed to create the local Python environment"
    }
    & $venvPython -m pip install --disable-pip-version-check --quiet -r (Join-Path $PSScriptRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "failed to install deployment dependencies"
    }
}

& $venvPython (Join-Path $PSScriptRoot "deploy.py") @DeployArgs
exit $LASTEXITCODE
