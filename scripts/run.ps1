$ErrorActionPreference = "Stop"

$PythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $PythonCommand) {
    $Python = $PythonCommand.Source
    $PythonPrefix = @("-3")
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $PythonCommand) {
        Write-Error "GARBAGE requires Python 3.10 or newer. Install Python and try again."
        exit 127
    }
    $Python = $PythonCommand.Source
    $PythonPrefix = @()
}

$Version = & $Python @PythonPrefix -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or [version]$Version -lt [version]"3.10") {
    Write-Error "GARBAGE requires Python 3.10 or newer; found $Version."
    exit 2
}

Push-Location (Join-Path $PSScriptRoot "..")
try {
    & $Python @PythonPrefix -m garbage_intel @args
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
