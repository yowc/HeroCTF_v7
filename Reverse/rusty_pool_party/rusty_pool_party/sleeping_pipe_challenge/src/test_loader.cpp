// Simple shellcode loader for testing
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <shellcode.bin> [entry_point_offset]\n", argv[0]);
        return 1;
    }

    // Get optional entry point offset
    DWORD entryOffset = 0;
    if (argc == 3) {
        entryOffset = strtoul(argv[2], NULL, 0);
        printf("[+] Using entry point offset: 0x%lx (%lu bytes)\n", entryOffset, entryOffset);
    }

    // Read shellcode from file
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open file: %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[+] Shellcode size: %lu bytes\n", fileSize);

    LPVOID shellcode = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

    // Change protection to RWX
    DWORD oldProtect;
    if (!VirtualProtect(shellcode, fileSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtect failed\n");
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Executing shellcode...\n");
    printf("[+] First 32 bytes: ");
    for (DWORD i = 0; i < 32 && i < fileSize; i++) {
        printf("%02X ", ((unsigned char*)shellcode)[i]);
    }
    printf("\n");

    // Flush output before execution
    fflush(stdout);

    // Execute shellcode at entry point offset
    typedef void (*ShellcodeFunc)();
    LPVOID entryPoint = (LPVOID)((BYTE*)shellcode + entryOffset);
    ShellcodeFunc func = (ShellcodeFunc)entryPoint;

    printf("[+] Calling shellcode at address: %p (offset 0x%lx)\n", (void*)func, entryOffset);
    fflush(stdout);

    func();

    printf("[+] Shellcode returned!\n");
    fflush(stdout);

    // Cleanup
    VirtualFree(shellcode, 0, MEM_RELEASE);

    return 0;
}
