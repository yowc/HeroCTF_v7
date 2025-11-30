# Test script for debugging injected master shellcode
# Runs FILE, COM, ALARM as standalone .exes
# Runs MASTER as injected shellcode for debugging

Write-Host "=== Debug Injected Master Test ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script tests master shellcode in simulated injection context"
Write-Host "All other shellcodes run as standalone executables"
Write-Host ""

# Start C2 server
Write-Host "[1] Starting Python C2 server..." -ForegroundColor Yellow
$c2Process = Start-Process -FilePath "cmd.exe" -ArgumentList "/k python c2_server.py" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 2

# Start file shellcode
Write-Host "[2] Starting file_shellcode.exe..." -ForegroundColor Yellow
$fileProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\file_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 1

# Start COM shellcode
Write-Host "[3] Starting com_shellcode.exe..." -ForegroundColor Yellow
$comProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\com_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 1

# Start MASTER shellcode via debug loader (simulates injection)
Write-Host "[4] Starting MASTER shellcode (injected simulation)..." -ForegroundColor Yellow
Write-Host "    This will wait 10 seconds for debugger attachment" -ForegroundColor Cyan
$masterProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\debug_injected_master.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 12  # Wait for the 10-second debugger delay + 2 extra

# Start alarm shellcode (triggers the chain)
Write-Host "[5] Starting alarm_shellcode.exe (triggers master)..." -ForegroundColor Yellow
$alarmProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\alarm_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 8

Write-Host ""
Write-Host "=== All processes started ===" -ForegroundColor Green
Write-Host ""
Write-Host "Debug the MASTER process:" -ForegroundColor Yellow
Write-Host "  1. Attach debugger to debug_injected_master.exe before 10 seconds"
Write-Host "  2. Set breakpoint at shellcode entry (shown in console output)"
Write-Host "  3. Step through to find where connection fails"
Write-Host ""
Write-Host "Press Enter to stop all processes and cleanup..." -ForegroundColor Yellow
Read-Host

# Cleanup
Write-Host ""
Write-Host "[*] Stopping all processes..." -ForegroundColor Yellow
Stop-Process -Id $c2Process.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $fileProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $comProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $masterProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $alarmProcess.Id -Force -ErrorAction SilentlyContinue

Write-Host "[*] Cleanup complete" -ForegroundColor Green
