# Smoke tests for nidhunt on Windows PowerShell. Run after building:
#   .\tests\run_tests.ps1
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')

$cpu = '.\nidhunt.exe'
$gpu = '.\nidhunt-gpu.exe'
if (-not (Test-Path $cpu)) { Write-Error "build first: $cpu not found"; exit 1 }

$script:pass = 0; $script:fail = 0
function Check($name, $want, $exe, $cliArgs) {
    $out = (& $exe @cliArgs 2>&1 | Out-String)
    if ($out -match [regex]::Escape($want)) {
        Write-Host "ok   - $name"; $script:pass++
    } else {
        Write-Host "FAIL - $name (wanted: $want)"; ($out -split "`n" | ForEach-Object { "       $_" }); $script:fail++
    }
}

Write-Host '== self-test =='
Check 'self-test' 'self-test OK' $cpu @('--self-test')

Write-Host '== CPU recovery =='
Check 'cpu combinator' 'HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext' $cpu `
    @('-t','tests/targets_selftest.txt','-p','sceNp','-v','tests/vocab_selftest.txt','-d','4')
Check 'cpu grammar' 'HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext' $cpu `
    @('-t','tests/targets_selftest.txt','-s','tests/slot_selftest.txt')
Check 'cpu suffix' 'HIT 23LRUSvYu1M sceAgcInit_0090' $cpu `
    @('-t','tests/targets_suffix.txt','-p','sceAgc','-s','tests/vocab_suffix.txt','-S','tests/suffixes_suffix.txt')

if (Test-Path $gpu) {
    Write-Host '== GPU recovery =='
    Check 'gpu combinator' 'HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext' $gpu `
        @('--backend','gpu','-t','tests/targets_selftest.txt','-p','sceNp','-v','tests/vocab_selftest.txt','-d','4')
    Check 'gpu suffix' 'HIT 23LRUSvYu1M sceAgcInit_0090' $gpu `
        @('--backend','gpu','-t','tests/targets_suffix.txt','-p','sceAgc','-s','tests/vocab_suffix.txt','-S','tests/suffixes_suffix.txt')
} else {
    Write-Host "(skip GPU tests: $gpu not built)"
}

Write-Host "== $($script:pass) passed, $($script:fail) failed =="
if ($script:fail -ne 0) { exit 1 }
