#include <windows.h>

// DLL Proxy
HMODULE hOriginal = NULL;
void *pGetFileVersionInfoA, *pGetFileVersionInfoByHandle, *pGetFileVersionInfoExA, *pGetFileVersionInfoExW;
void *pGetFileVersionInfoSizeA, *pGetFileVersionInfoSizeExA, *pGetFileVersionInfoSizeExW, *pGetFileVersionInfoSizeW;
void *pGetFileVersionInfoW, *pVerFindFileA, *pVerFindFileW, *pVerInstallFileA, *pVerInstallFileW;
void *pVerLanguageNameA, *pVerLanguageNameW, *pVerQueryValueA, *pVerQueryValueW;

__declspec(naked) void _GetFileVersionInfoA() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoA)); }
__declspec(naked) void _GetFileVersionInfoByHandle() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoByHandle)); }
__declspec(naked) void _GetFileVersionInfoExA() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoExA)); }
__declspec(naked) void _GetFileVersionInfoExW() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoExW)); }
__declspec(naked) void _GetFileVersionInfoSizeA() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoSizeA)); }
__declspec(naked) void _GetFileVersionInfoSizeExA() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoSizeExA)); }
__declspec(naked) void _GetFileVersionInfoSizeExW() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoSizeExW)); }
__declspec(naked) void _GetFileVersionInfoSizeW() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoSizeW)); }
__declspec(naked) void _GetFileVersionInfoW() { __asm__ ("jmp *%0" :: "m" (pGetFileVersionInfoW)); }
__declspec(naked) void _VerFindFileA() { __asm__ ("jmp *%0" :: "m" (pVerFindFileA)); }
__declspec(naked) void _VerFindFileW() { __asm__ ("jmp *%0" :: "m" (pVerFindFileW)); }
__declspec(naked) void _VerInstallFileA() { __asm__ ("jmp *%0" :: "m" (pVerInstallFileA)); }
__declspec(naked) void _VerInstallFileW() { __asm__ ("jmp *%0" :: "m" (pVerInstallFileW)); }
__declspec(naked) void _VerLanguageNameA() { __asm__ ("jmp *%0" :: "m" (pVerLanguageNameA)); }
__declspec(naked) void _VerLanguageNameW() { __asm__ ("jmp *%0" :: "m" (pVerLanguageNameW)); }
__declspec(naked) void _VerQueryValueA() { __asm__ ("jmp *%0" :: "m" (pVerQueryValueA)); }
__declspec(naked) void _VerQueryValueW() { __asm__ ("jmp *%0" :: "m" (pVerQueryValueW)); }

void InitProxy()
{
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    lstrcatA(path, "\\version.dll");
    hOriginal = LoadLibraryA(path);
    pGetFileVersionInfoA = GetProcAddress(hOriginal, "GetFileVersionInfoA");
    pGetFileVersionInfoByHandle = GetProcAddress(hOriginal, "GetFileVersionInfoByHandle");
    pGetFileVersionInfoExA = GetProcAddress(hOriginal, "GetFileVersionInfoExA");
    pGetFileVersionInfoExW = GetProcAddress(hOriginal, "GetFileVersionInfoExW");
    pGetFileVersionInfoSizeA = GetProcAddress(hOriginal, "GetFileVersionInfoSizeA");
    pGetFileVersionInfoSizeExA = GetProcAddress(hOriginal, "GetFileVersionInfoSizeExA");
    pGetFileVersionInfoSizeExW = GetProcAddress(hOriginal, "GetFileVersionInfoSizeExW");
    pGetFileVersionInfoSizeW = GetProcAddress(hOriginal, "GetFileVersionInfoSizeW");
    pGetFileVersionInfoW = GetProcAddress(hOriginal, "GetFileVersionInfoW");
    pVerFindFileA = GetProcAddress(hOriginal, "VerFindFileA");
    pVerFindFileW = GetProcAddress(hOriginal, "VerFindFileW");
    pVerInstallFileA = GetProcAddress(hOriginal, "VerInstallFileA");
    pVerInstallFileW = GetProcAddress(hOriginal, "VerInstallFileW");
    pVerLanguageNameA = GetProcAddress(hOriginal, "VerLanguageNameA");
    pVerLanguageNameW = GetProcAddress(hOriginal, "VerLanguageNameW");
    pVerQueryValueA = GetProcAddress(hOriginal, "VerQueryValueA");
    pVerQueryValueW = GetProcAddress(hOriginal, "VerQueryValueW");
}

// IAT Hooking Code
void* HookFunction(const wchar_t* moduleName, const char* functionName, void* replaceWith)
{
    const char* moduleBase = (const char*)GetModuleHandleW(moduleName);
    if (!moduleBase) return NULL;
    
    const IMAGE_DOS_HEADER* dosHeader = (const IMAGE_DOS_HEADER*)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    const IMAGE_NT_HEADERS* ntHeaders = (const IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    const IMAGE_DATA_DIRECTORY* dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dataDirectory->Size == 0 || dataDirectory->VirtualAddress == 0) return NULL;
    
    const IMAGE_IMPORT_DESCRIPTOR* importDesc = (const IMAGE_IMPORT_DESCRIPTOR*)(moduleBase + dataDirectory->VirtualAddress);
    
    for (; importDesc->FirstThunk; ++importDesc) {
        const IMAGE_THUNK_DATA* thunkNames = (const IMAGE_THUNK_DATA*)(moduleBase + importDesc->OriginalFirstThunk);
        const IMAGE_THUNK_DATA* thunkAddresses = (const IMAGE_THUNK_DATA*)(moduleBase + importDesc->FirstThunk);
        
        for (; thunkAddresses->u1.Function; ++thunkAddresses, ++thunkNames) {
            if ((thunkNames->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
                const IMAGE_IMPORT_BY_NAME* importByName = (const IMAGE_IMPORT_BY_NAME*)(moduleBase + thunkNames->u1.AddressOfData);
                const char* importedFunctionName = (const char*)importByName->Name;
                void** importedFunctionLoadAddress = (void**)&thunkAddresses->u1.Function;
                
                if (strcmp(functionName, importedFunctionName) == 0) {
                    void* originalAddress = *importedFunctionLoadAddress;
                    DWORD oldProtect;
                    VirtualProtect(importedFunctionLoadAddress, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    memcpy(importedFunctionLoadAddress, &replaceWith, sizeof(replaceWith));
                    VirtualProtect(importedFunctionLoadAddress, sizeof(void*), oldProtect, &oldProtect);
                    return originalAddress;
                }
            }
        }
    }
    
    return NULL;
}

// Payloads
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef HANDLE (WINAPI *CreateNamedPipeW_t)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef BOOL (WINAPI *ConnectNamedPipe_t)(HANDLE, LPOVERLAPPED);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

LoadLibraryW_t OriginalLoadLibraryW = NULL;
CreateNamedPipeW_t OriginalCreateNamedPipeW = NULL;
ConnectNamedPipe_t OriginalConnectNamedPipe = NULL;
WriteFile_t OriginalWriteFile = NULL;

#define PIPE_BUFFER_SIZE 16
HANDLE pendingPipeHandles[PIPE_BUFFER_SIZE] = {[0 ... PIPE_BUFFER_SIZE - 1] = INVALID_HANDLE_VALUE};

HANDLE WINAPI HookedCreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    // disable NOWAIT just in case
    dwPipeMode &= ~PIPE_NOWAIT;
    HANDLE hPipe = OriginalCreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    for (int i = 0; i < PIPE_BUFFER_SIZE; i++) {
        if (pendingPipeHandles[i] == INVALID_HANDLE_VALUE) {
            pendingPipeHandles[i] = hPipe;
            break;
        }
    }
    return hPipe;
}

BOOL WINAPI HookedConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
{
    BOOL result = OriginalConnectNamedPipe(hNamedPipe, lpOverlapped);
    for (int i = 0; i < PIPE_BUFFER_SIZE; i++) {
        if (pendingPipeHandles[i] == hNamedPipe) {
            pendingPipeHandles[i] = INVALID_HANDLE_VALUE;
            break;
        }
    }
    return result;
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    // The race condition is here: The program writes to the pipe before ConnectNamedPipe is called.
    // So much of the initialization data is lost and the program stalls.
    // Sleep for a short time to allow ConnectNamedPipe to be called first.
    for (int i = 0; i < PIPE_BUFFER_SIZE; i++) {
        if (pendingPipeHandles[i] == hFile) {
            Sleep(50);
            break;
        }
    }
    return OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE result = OriginalLoadLibraryW(lpLibFileName);
    if (lpLibFileName && wcsstr(lpLibFileName, L"VersionServiceProxy.dll")) {
        OriginalCreateNamedPipeW = (CreateNamedPipeW_t)HookFunction(L"VersionServiceProxy.dll", "CreateNamedPipeW", HookedCreateNamedPipeW);
        OriginalConnectNamedPipe = (ConnectNamedPipe_t)HookFunction(L"VersionServiceProxy.dll", "ConnectNamedPipe", HookedConnectNamedPipe);
        OriginalWriteFile = (WriteFile_t)HookFunction(L"VersionServiceProxy.dll", "WriteFile", HookedWriteFile);
    }
    return result;
}

void Hook()
{
    OriginalLoadLibraryW = (LoadLibraryW_t)HookFunction(NULL, "LoadLibraryW", HookedLoadLibraryW);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitProxy();
        Hook();
    }
    return TRUE;
}