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
Check 'cpu two-block' 'HIT XOUAK95mhQ0' $cpu `
    @('-t','tests/targets_twoblock.txt','-s','tests/slot_twoblock.txt')
$env:NIDHUNT_NO_NI = '1'
Check 'cpu scalar' 'HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext' $cpu `
    @('-t','tests/targets_selftest.txt','-p','sceNp','-v','tests/vocab_selftest.txt','-d','4')
Remove-Item Env:\NIDHUNT_NO_NI

Write-Host '== input validation =='
$out = (& $cpu @('-t','tests/targets_selftest.txt','-s','tests/slot_selftest.txt','-s','tests/empty.txt') 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -and $out -match 'no usable words') {
    Write-Host 'ok   - empty slot rejected'; $script:pass++
} else { Write-Host 'FAIL - empty slot rejected'; $script:fail++ }

if (Test-Path $gpu) {
    Write-Host '== GPU recovery =='
    Check 'gpu combinator' 'HIT GtuZGmN-tKw sceNpSessionSignalingCreateContext' $gpu `
        @('--backend','gpu','-t','tests/targets_selftest.txt','-p','sceNp','-v','tests/vocab_selftest.txt','-d','4')
    Check 'gpu suffix' 'HIT 23LRUSvYu1M sceAgcInit_0090' $gpu `
        @('--backend','gpu','-t','tests/targets_suffix.txt','-p','sceAgc','-s','tests/vocab_suffix.txt','-S','tests/suffixes_suffix.txt')
    Check 'gpu two-block' 'HIT XOUAK95mhQ0' $gpu `
        @('--backend','gpu','-t','tests/targets_twoblock.txt','-s','tests/slot_twoblock.txt')
    Write-Host '== CPU/GPU parity =='
    $pc = (& $cpu @('-t','tests/targets_parity.txt','-p','sceVideoOut','-v','tests/vocab_parity.txt','-d','1') 2>$null | Select-String '^HIT' | Sort-Object | Out-String)
    $pg = (& $gpu @('--backend','gpu','-t','tests/targets_parity.txt','-p','sceVideoOut','-v','tests/vocab_parity.txt','-d','1') 2>$null | Select-String '^HIT' | Sort-Object | Out-String)
    if ($pc.Trim() -and $pc -eq $pg) { Write-Host 'ok   - cpu/gpu parity'; $script:pass++ }
    else { Write-Host 'FAIL - cpu/gpu parity'; $script:fail++ }
} else {
    Write-Host "(skip GPU tests: $gpu not built)"
}

$py = $null
foreach ($cand in @('python3','python','py')) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        try { & $cand -c "import sys" 2>$null; if ($LASTEXITCODE -eq 0) { $py = $cand; break } } catch {}
    }
}
if ($py) {
    Write-Host '== vocab.py =='
    Check 'vocab nid' 'GtuZGmN-tKw' $py @('tools/vocab.py','nid','sceNpSessionSignalingCreateContext')
    Check 'vocab check' 'OK GtuZGmN-tKw' $py @('tools/vocab.py','check','sceNpSessionSignalingCreateContext','GtuZGmN-tKw')
    Check 'vocab rank' 'Out' $py @('tools/vocab.py','words','--symbols','tests/symbols_sample.txt','--prefix','sce','--rank')
    & $py @('tools/vocab.py','positions','--symbols','tests/symbols_sample.txt','--prefix','sceVideoOut','--out',"$env:TEMP\nh_pos") 2>&1 | Out-Null
    if (Test-Path "$env:TEMP\nh_pos_1.txt") { Write-Host 'ok   - vocab positions'; $script:pass++ }
    else { Write-Host 'FAIL - vocab positions'; $script:fail++ }
} else {
    Write-Host '(skip vocab.py tests: no working python)'
}

Write-Host "== $($script:pass) passed, $($script:fail) failed =="
if ($script:fail -ne 0) { exit 1 }
