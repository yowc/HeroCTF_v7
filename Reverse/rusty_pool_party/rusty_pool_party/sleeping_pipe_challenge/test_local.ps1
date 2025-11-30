# Sleeping Pipe CTF Challenge - Local Test Script
# PowerShell script to test shellcode communication flow

Write-Host "=== Sleeping Pipe CTF Challenge - Local Test ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script tests the shellcode communication flow locally"
Write-Host "All shellcodes run as standalone executables with debug output"
Write-Host ""

# Create initial flag files for the challenge
# Write-Host "[0] Creating initial flag files..." -ForegroundColor Yellow
# $appdata = $env:APPDATA
# $flag1Path = Join-Path $appdata "flag_1.txt"

# Create empty flag_1.txt - shellcode will write flag part 1 here
# "" | Out-File -FilePath $flag1Path -Encoding ASCII -NoNewline
# Write-Host "    Created $flag1Path (empty - ready for flag part 1)" -ForegroundColor Green

# Create registry key structure for flag_2
# Note: Shellcode will write flag part 2 to HKCU\Software\CTF\flag_2
# Write-Host "    Registry key HKCU\Software\CTF\flag_2 will be created by shellcode" -ForegroundColor Yellow

# Start Python C2 server (keep window open with cmd /k)
Write-Host "[1] Starting Python C2 server on 127.0.0.1:8080..." -ForegroundColor Yellow
$c2Process = Start-Process -FilePath "cmd.exe" -ArgumentList "/k python c2_server.py" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 2

# Start file shellcode (keep window open with cmd /k)
Write-Host "[2] Starting file_shellcode (waiting on \\.\pipe\file)..." -ForegroundColor Yellow
$fileProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\file_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 1

# Start com shellcode (keep window open with cmd /k)
Write-Host "[3] Starting com_shellcode (waiting on \\.\pipe\com)..." -ForegroundColor Yellow
$comProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\com_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 1

# Start master shellcode (keep window open with cmd /k)
Write-Host "[4] Starting pipe_master_shellcode (waiting on \\.\pipe\master)..." -ForegroundColor Yellow
$masterProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\pipe_master_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 1

# Trigger the chain with alarm shellcode (keep window open with cmd /k)
Write-Host "[5] Triggering alarm_shellcode (connects to master after 5s delay)..." -ForegroundColor Yellow
$alarmProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/k bin\alarm_shellcode.exe" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 8  # Give alarm time to run (5s delay + execution time)

# Note: Since we're using cmd /k, processes don't return exit codes directly
Write-Host ""
Write-Host "NOTE: All windows will stay open to show output (using cmd /k)" -ForegroundColor Cyan
$alarmExit = 0  # Can't get real exit code with cmd /k

Write-Host ""
Write-Host "=== Test Execution Flow ===" -ForegroundColor Cyan
Write-Host "Alarm exit code: $alarmExit" -ForegroundColor $(if ($alarmExit -eq 0) { "Green" } else { "Red" })
Write-Host ""
Write-Host "The chain should execute as follows:"
Write-Host "  1. Alarm sleeps 5s, then sends WAKEUP to master"
Write-Host "  2. Master wakes, sends READY to com"
Write-Host "  3. COM makes HTTP GET to C2, receives RC4-encrypted command"
Write-Host "  4. COM forwards command to master"
Write-Host "  5. Master decrypts command (file path), sends to file shellcode"
Write-Host "  6. File reads file, returns content to master"
Write-Host "  7. Master sends content to COM"
Write-Host "  8. COM POSTs response to C2"
Write-Host "  9. Repeat for second command, then C2 sends FLAG"
Write-Host ""
Write-Host "Check the console windows for debug output from each shellcode" -ForegroundColor Yellow
Write-Host "The windows will stay open even after processes exit/crash" -ForegroundColor Yellow
Write-Host "You can scroll back to see the full output including crash details" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Enter to close all windows and cleanup..." -ForegroundColor Yellow
Read-Host

# Cleanup - kill cmd.exe processes hosting our shellcodes
Write-Host ""
Write-Host "[*] Stopping all processes and closing windows..." -ForegroundColor Yellow
Stop-Process -Id $c2Process.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $fileProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $comProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $masterProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $alarmProcess.Id -Force -ErrorAction SilentlyContinue

# Clean up test files
$flag1Path = Join-Path $env:APPDATA "flag_1.txt"
Remove-Item $flag1Path -ErrorAction SilentlyContinue

# Note: Registry key cleanup would be done manually if needed
Write-Host "[!] Note: To clean up registry, run: Remove-Item 'HKCU:\Software\CTF' -Recurse -ErrorAction SilentlyContinue" -ForegroundColor Yellow

Write-Host "[*] Cleanup complete" -ForegroundColor Green
