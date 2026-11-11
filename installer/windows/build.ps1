param(
    [Parameter(Mandatory = $true)]
    [string] $UpxDirectory,
    [string] $Python = "python",
    [string] $InnoCompiler = "ISCC.exe",
    [string] $OutputDirectory
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$upx = (Resolve-Path $UpxDirectory).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root "dist\windows"
}
foreach ($file in @("upx.exe", "COPYING", "LICENSE")) {
    if (-not (Test-Path -LiteralPath (Join-Path $upx $file) -PathType Leaf)) {
        throw "UPX distribution is missing $file in $upx."
    }
}

$platform = & $Python -c "import sysconfig; print(sysconfig.get_platform())"
if ($LASTEXITCODE -ne 0 -or $platform -ne "win-amd64") {
    throw "A working x64 Windows Python is required."
}
& $Python -m PyInstaller --version
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is not installed in the selected Python environment."
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("aisa-build-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    & $Python -m PyInstaller --noconfirm --noupx --onedir --console --name aisa `
        --paths $root `
        --add-data "$(Join-Path $root 'models\string_model_weights.json');models" `
        --distpath (Join-Path $staging "dist") `
        --workpath (Join-Path $staging "work") `
        --specpath $staging `
        (Join-Path $root "main.py")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE." }

    $app = Join-Path $staging "dist\aisa"
    $appUpx = Join-Path $app "upx"
    New-Item -ItemType Directory -Path $appUpx | Out-Null
    Copy-Item -LiteralPath (Join-Path $upx "upx.exe") -Destination $appUpx
    Copy-Item -LiteralPath (Join-Path $upx "COPYING") -Destination $appUpx
    Copy-Item -LiteralPath (Join-Path $upx "LICENSE") -Destination $appUpx
    & (Join-Path $appUpx "upx.exe") --version
    if ($LASTEXITCODE -ne 0) { throw "The bundled UPX executable could not run." }
    & $Python (Join-Path $PSScriptRoot "smoke_test.py") (Join-Path $app "aisa.exe")
    if ($LASTEXITCODE -ne 0) { throw "The packaged AISA executable failed its smoke test." }
    & $InnoCompiler "/DAppSource=$app" "/DOutputDir=$output" `
        (Join-Path $PSScriptRoot "aisa.iss")
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed with exit code $LASTEXITCODE." }
    Write-Host "Installer created in $output"
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force
}
