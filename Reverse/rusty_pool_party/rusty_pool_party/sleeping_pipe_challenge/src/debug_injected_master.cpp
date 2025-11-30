// Debug loader for testing pipe_master shellcode in injected context
// This simulates injection by loading shellcode into current process
// Adds delay for debugger attachment
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    const char* shellcode_path = "bin/pipe_master_shellcode.bin";

    if (argc > 1) {
        shellcode_path = argv[1];
    }

    printf("[*] Debug Injected Master Loader\n");
    printf("[*] Shellcode: %s\n", shellcode_path);
    printf("[*] PID: %lu\n", GetCurrentProcessId());
    printf("\n[!] Waiting 10 seconds for debugger attachment...\n");
    printf("[!] Attach debugger now and set breakpoints!\n");
    fflush(stdout);

    // Wait for debugger attachment
    for (int i = 10; i > 0; i--) {
        printf("    %d seconds remaining...\n", i);
        fflush(stdout);
        Sleep(1000);
    }

    printf("\n[+] Loading shellcode from: %s\n", shellcode_path);
    fflush(stdout);

    // Read shellcode
    HANDLE hFile = CreateFileA(shellcode_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open shellcode file\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[+] Shellcode size: %lu bytes\n", fileSize);

    // Allocate RWX memory
    LPVOID shellcode = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        printf("[!] VirtualAlloc failed\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL)) {
        printf("[!] ReadFile failed\n");
        VirtualFree(shellcode, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    printf("[+] Shellcode loaded at: %p\n", shellcode);
    printf("[+] Shellcode bytes: ");
    for (DWORD i = 0; i < 32 && i < fileSize; i++) {
        printf("%02X ", ((unsigned char*)shellcode)[i]);
    }
    printf("\n\n");
    fflush(stdout);

    printf("[+] Executing shellcode (simulating injection)...\n");
    printf("[!] If shellcode fails, it will go into idle mode\n");
    printf("[!] Monitor CPU usage - high CPU means busy-wait idle\n");
    fflush(stdout);

    // Execute shellcode as thread (similar to injection)
    typedef DWORD (WINAPI *ShellcodeFunc)(LPVOID);
    ShellcodeFunc func = (ShellcodeFunc)shellcode;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateThread failed\n");
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Shellcode thread created (TID: %lu)\n", GetThreadId(hThread));
    printf("[+] Waiting for shellcode to complete (or go idle)...\n");
    printf("[!] Press Ctrl+C to exit\n\n");
    fflush(stdout);

    // Wait forever (shellcode will run in background)
    WaitForSingleObject(hThread, INFINITE);

    printf("[+] Shellcode thread exited\n");
    CloseHandle(hThread);
    VirtualFree(shellcode, 0, MEM_RELEASE);

    return 0;
}
