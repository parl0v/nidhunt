# Build nidhunt on Windows with MinGW (GCC).
# Produces nidhunt.exe (CPU) and, when the OpenCL loader is present,
# nidhunt-gpu.exe (CPU + GPU backends).
#
#   .\build.ps1            # autodetect OpenCL
#   .\build.ps1 cpu        # CPU binary only
#   .\build.ps1 gpu        # require OpenCL, fail if missing
#
# g++ must be on PATH (e.g. the MinGW-w64 bin directory).
param([ValidateSet('auto','cpu','gpu')][string]$Mode = 'auto')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$cxx = 'g++'
$flags = @('-O3','-std=c++17','-Wall','-Wextra')

Write-Host 'building nidhunt.exe (CPU)'
& $cxx @flags -pthread src/nidhunt.cpp -o nidhunt.exe
if ($LASTEXITCODE -ne 0) { throw 'CPU build failed' }

if ($Mode -eq 'cpu') { return }

$ocl = Join-Path $env:SystemRoot 'System32\OpenCL.dll'
$link = if (Test-Path $ocl) { $ocl } else { '-lOpenCL' }

Write-Host 'building nidhunt-gpu.exe (CPU + GPU)'
& $cxx @flags -pthread -DNIDHUNT_OPENCL -Isrc src/nidhunt.cpp $link -o nidhunt-gpu.exe
if ($LASTEXITCODE -ne 0) {
    if ($Mode -eq 'gpu') { throw 'GPU build failed (OpenCL loader not found)' }
    Write-Warning 'OpenCL not available; built CPU binary only'
}
