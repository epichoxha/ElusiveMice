#include "refresh.h"


// void dprintf(const char*, ...);
#define dprintf


typedef void(__cdecl* FREE)(void*);
typedef void(__cdecl* __MOVSB)(unsigned char*, unsigned const char*, size_t);
typedef void* (__cdecl* CALLOC)(size_t, size_t);
typedef int(__cdecl* MBSTOWCS_S)(size_t*, wchar_t*, size_t, const char*, size_t);
typedef int(__cdecl* _WCSNICMP)(const wchar_t*, const wchar_t*, size_t);
typedef size_t(__cdecl* STRNLEN)(const char*, size_t);
typedef size_t(__cdecl* STRLEN)(const char*);
typedef int(__cdecl* STRCMP)(const char*, const char*);
typedef int(__cdecl* WCSCMP)(const wchar_t*, const wchar_t*);
typedef int(__cdecl* MEMCMP)(const void* ptr1, const void* ptr2, size_t num);
typedef const char* (__cdecl* STRSTR)(const char* str1, const char* str2);
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef HANDLE(WINAPI* CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CREATEFILEMAPPINGW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID(WINAPI* MAPVIEWOFFILE)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* UNMAPVIEWOFFILE)(LPCVOID);
typedef void (WINAPI* CLOSEHANDLE)(HANDLE);
typedef HMODULE(WINAPI* LOADLIBRARYW)(LPCWSTR);
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* GETMODULEHANDLEW)(LPCWSTR);
typedef void (WINAPI* OUTPUTDEBUGSTR)(const char*);

struct FunctionPointers {
    FREE pfree;
    __MOVSB p__movsb;
    CALLOC pcalloc;
    MBSTOWCS_S pmbstowcs_s;
    _WCSNICMP p_wcsnicmp;
    STRLEN pstrlen;
    STRCMP pstrcmp;
    WCSCMP pwcscmp;
    MEMCMP pmemcmp;
    STRSTR pstrstr;
    STRNLEN pstrnlen;
    VIRTUALFREE pVirtualFree;
    CREATEFILEW pCreateFileW;
    CREATEFILEMAPPINGW pCreateFileMappingW;
    MAPVIEWOFFILE pMapViewOfFile;
    VIRTUALALLOC pVirtualAlloc;
    UNMAPVIEWOFFILE pUnmapViewOfFile;
    CLOSEHANDLE pCloseHandle;
    LOADLIBRARYW pLoadLibraryW;
    VIRTUALPROTECT pVirtualProtect;
    GETMODULEHANDLEW pGetModuleHandleW;
    OUTPUTDEBUGSTR pOutputDebugStringA;
};



_PPEB GetProcessEnvironmentBlock()
{
    ULONG_PTR pPeb;
#ifdef _WIN64
    pPeb = __readgsqword(0x60);
#else
#ifdef WIN_ARM
    pPeb = *(DWORD*)((BYTE*)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#else _WIN32
    pPeb = __readfsdword(0x30);
#endif
#endif
    return (_PPEB)pPeb;
}

PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList()
{
    return (PLDR_DATA_TABLE_ENTRY)GetProcessEnvironmentBlock()->pLdr->InMemoryOrderModuleList.Flink;
}

PWCHAR GetRedirectedName(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->pFreeList;
    *stSize = 0;

    if (pApiSetMap->Version == 6)
        return GetRedirectedName_V6(fptrs, wszImportingModule, wszVirtualModule, stSize);
    else if (pApiSetMap->Version == 4)
        return GetRedirectedName_V4(fptrs, wszImportingModule, wszVirtualModule, stSize);
    else if (pApiSetMap->Version == 2)
        return GetRedirectedName_V2(fptrs, wszImportingModule, wszVirtualModule, stSize);
    else
        return NULL;
}

PWCHAR GetRedirectedName_V6(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V6 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V6 pApiEntry;
    PAPI_SET_VALUE_ENTRY_V6 pApiValue;
    PAPI_SET_VALUE_ENTRY_V6 pApiArray;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;

    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V6)GetProcessEnvironmentBlock()->pFreeList;

    // Loop through each entry in the ApiSetMap to find the matching redirected module entry
    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        // Skip this entry if it does not match
        if (fptrs->p_wcsnicmp(wsEntry, wszVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ENTRY_V6)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        // Loop through each value entry from the end and find where the importing module matches the ``Name`` entry
        // If the ``Name`` entry is empty, it is the default entry @ index = 0
        for (dwSetCount = pApiEntry->Count - 1; dwSetCount >= 0; dwSetCount--)
        {
            // pApiValue = (PAPI_SET_VALUE_ENTRY_V6)((PCHAR)pApiSetMap + pApiEntry->DataOffset + (dwSetCount * sizeof(API_SET_VALUE_ENTRY_V6)));
            pApiValue = &pApiArray[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || fptrs->p_wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}


PWCHAR GetRedirectedName_V4(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V4 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V4 pApiArray;
    PAPI_SET_VALUE_ENTRY_V4 pApiValue;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;
    PWSTR wszShortVirtualModule;

    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V4)GetProcessEnvironmentBlock()->pFreeList;
    wszShortVirtualModule = (PWSTR)((PWCHAR)wszVirtualModule + 4);

    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        if (fptrs->p_wcsnicmp(wsEntry, wszShortVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ARRAY_V4)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count - 1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || fptrs->p_wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}

PWCHAR GetRedirectedName_V2(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
{
    PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY_V2 pApiEntry;
    PAPI_SET_VALUE_ARRAY_V2 pApiArray;
    PAPI_SET_VALUE_ENTRY_V2 pApiValue;
    DWORD dwEntryCount;
    LONG dwSetCount;
    PWSTR wsEntry;
    PWSTR wsName;
    PWSTR wsValue;
    PWSTR wszShortVirtualModule;

    pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY_V2)GetProcessEnvironmentBlock()->pFreeList;
    wszShortVirtualModule = (PWSTR)((PWCHAR)wszVirtualModule + 4);

    for (dwEntryCount = 0; dwEntryCount < pApiSetMap->Count; dwEntryCount++)
    {
        pApiEntry = &pApiSetMap->Array[dwEntryCount];
        wsEntry = (PWSTR)((PCHAR)pApiSetMap + pApiEntry->NameOffset);

        if (fptrs->p_wcsnicmp(wsEntry, wszShortVirtualModule, pApiEntry->NameLength / 2) != 0)
            continue;

        pApiArray = (PAPI_SET_VALUE_ARRAY_V2)((PCHAR)pApiSetMap + pApiEntry->DataOffset);

        for (dwSetCount = pApiArray->Count - 1; dwSetCount >= 0; dwSetCount--)
        {
            pApiValue = &pApiArray->Array[dwSetCount];
            wsName = (PWSTR)((PCHAR)pApiSetMap + pApiValue->NameOffset);
            wsValue = (PWSTR)((PCHAR)pApiSetMap + pApiValue->ValueOffset);

            if (pApiValue->NameLength == 0 || fptrs->p_wcsnicmp(wsName, wszImportingModule, pApiValue->NameLength / 2) == 0)
            {
                *stSize = pApiValue->ValueLength / 2;
                return wsValue;
            }
        }
    }
    return NULL;
}


BOOL IsBeaconDLL(char* stomp, size_t beaconDllLength, PWSTR wszBaseDllName, USHORT BaseDllLength)
{
    BOOL isBeacon = FALSE;
    if (beaconDllLength * 2 == BaseDllLength)
    {
        isBeacon = TRUE;
        for (int i = 0; i < beaconDllLength; i++)
        {
            // make them lower case
            char c1 = stomp[i];
            char c2 = wszBaseDllName[i];
            if (c1 >= 'A' && c1 <= 'Z')
                c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z')
                c2 += 32;
            if (c1 != c2)
            {
                isBeacon = FALSE;
                break;
            }
        }
    }
    return isBeacon;
}

BOOL ResolveOwnImports(struct FunctionPointers* fptrs, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress)
{
    char buf0[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '\x00' };
    HMODULE hKernel32 = pLoadLibraryA(buf0);
    if (!hKernel32) {
        dprintf("ResolveOwnImports: could not load kernel32");
        return FALSE;
    }

    char buf01[] = { 'm', 's', 'v', 'c', 'r', 't', '\x00' };
    HMODULE hMsvcrt = pLoadLibraryA(buf01);
    if (!hMsvcrt) {
        dprintf("ResolveOwnImports: could not load msvcrt");
        return FALSE;
    }

    char buf1[] = { 'f', 'r', 'e', 'e', '\x00' };
    fptrs->pfree = (FREE)pGetProcAddress(hMsvcrt, buf1);
    if (!fptrs->pfree) {
        dprintf("ResolveOwnImports failed: free");
        return FALSE;
    }

    /*char buf2[] = { '_', '_', 'm', 'o', 'v', 's', 'b', '\x00' };
    __MOVSB __movsb = (__MOVSB)pGetProcAddress(hKernel32, buf2);
    if (!__movsb) {
        dprintf("ResolveOwnImports failed: __movsb");
        return FALSE;
    }*/

    char buf3[] = { 'c', 'a', 'l', 'l', 'o', 'c', '\x00' };
    fptrs->pcalloc = (CALLOC)pGetProcAddress(hMsvcrt, buf3);
    if (!fptrs->pcalloc) {
        dprintf("ResolveOwnImports failed: calloc");
        return FALSE;
    }

    char buf4[] = { 'm', 'b', 's', 't', 'o', 'w', 'c', 's', '_', 's', '\x00' };
    fptrs->pmbstowcs_s = (MBSTOWCS_S)pGetProcAddress(hMsvcrt, buf4);
    if (!fptrs->pmbstowcs_s) {
        dprintf("ResolveOwnImports failed: mbstowcs_s");
        return FALSE;
    }

    char buf5[] = { '_', 'w', 'c', 's', 'n', 'i', 'c', 'm', 'p', '\x00' };
    fptrs->p_wcsnicmp = (_WCSNICMP)pGetProcAddress(hMsvcrt, buf5);
    if (!fptrs->p_wcsnicmp) {
        dprintf("ResolveOwnImports failed: _wcsnicmp");
        return FALSE;
    }

    char buf6[] = { 's', 't', 'r', 'l', 'e', 'n', '\x00' };
    fptrs->pstrlen = (STRLEN)pGetProcAddress(hMsvcrt, buf6);
    if (!fptrs->pstrlen) {
        dprintf("ResolveOwnImports failed: strlen");
        return FALSE;
    }

    char buf7[] = { 's', 't', 'r', 'c', 'm', 'p', '\x00' };
    fptrs->pstrcmp = (STRCMP)pGetProcAddress(hMsvcrt, buf7);
    if (!fptrs->pstrcmp) {
        dprintf("ResolveOwnImports failed: strcmp");
        return FALSE;
    }

    char buf8[] = { 'w', 'c', 's', 'c', 'm', 'p', '\x00' };
    fptrs->pwcscmp = (WCSCMP)pGetProcAddress(hMsvcrt, buf8);
    if (!fptrs->pwcscmp) {
        dprintf("ResolveOwnImports failed: wcscmp");
        return FALSE;
    }

    char buf9[] = { 'm', 'e', 'm', 'c', 'm', 'p', '\x00' };
    fptrs->pmemcmp = (MEMCMP)pGetProcAddress(hMsvcrt, buf9);
    if (!fptrs->pmemcmp) {
        dprintf("ResolveOwnImports failed: memcmp");
        return FALSE;
    }

    char buf10[] = { 's', 't', 'r', 's', 't', 'r', '\x00' };
    fptrs->pstrstr = (STRSTR)pGetProcAddress(hMsvcrt, buf10);
    if (!fptrs->pstrstr) {
        dprintf("ResolveOwnImports failed: strstr");
        return FALSE;
    }

    char buf11[] = { 's', 't', 'r', 'n', 'l', 'e', 'n', '\x00' };
    fptrs->pstrnlen = (STRNLEN)pGetProcAddress(hMsvcrt, buf11);
    if (!fptrs->pstrnlen) {
        dprintf("ResolveOwnImports failed: strnlen");
        return FALSE;
    }

    char buf12[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\x00' };
    fptrs->pVirtualFree = (VIRTUALFREE)pGetProcAddress(hKernel32, buf12);
    if (!fptrs->pVirtualFree) {
        dprintf("ResolveOwnImports failed: VirtualFree");
        return FALSE;
    }

    char buf13[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', '\x00' };
    fptrs->pCreateFileW = (CREATEFILEW)pGetProcAddress(hKernel32, buf13);
    if (!fptrs->pCreateFileW) {
        dprintf("ResolveOwnImports failed: CreateFileW");
        return FALSE;
    }

    char buf14[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'W', '\x00' };
    fptrs->pCreateFileMappingW = (CREATEFILEMAPPINGW)pGetProcAddress(hKernel32, buf14);
    if (!fptrs->pCreateFileMappingW) {
        dprintf("ResolveOwnImports failed: CreateFileMappingW");
        return FALSE;
    }

    char buf15[] = { 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', '\x00' };
    fptrs->pMapViewOfFile = (MAPVIEWOFFILE)pGetProcAddress(hKernel32, buf15);
    if (!fptrs->pMapViewOfFile) {
        dprintf("ResolveOwnImports failed: MapViewOfFile");
        return FALSE;
    }

    char buf16[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\x00' };
    fptrs->pVirtualAlloc = (VIRTUALALLOC)pGetProcAddress(hKernel32, buf16);
    if (!fptrs->pVirtualAlloc) {
        dprintf("ResolveOwnImports failed: VirtualAlloc");
        return FALSE;
    }

    char buf17[] = { 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', '\x00' };
    fptrs->pUnmapViewOfFile = (UNMAPVIEWOFFILE)pGetProcAddress(hKernel32, buf17);
    if (!fptrs->pUnmapViewOfFile) {
        dprintf("ResolveOwnImports failed: UnmapViewOfFile");
        return FALSE;
    }

    char buf18[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\x00' };
    fptrs->pCloseHandle = (CLOSEHANDLE)pGetProcAddress(hKernel32, buf18);
    if (!fptrs->pCloseHandle) {
        dprintf("ResolveOwnImports failed: CloseHandle");
        return FALSE;
    }

    char buf19[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', '\x00' };
    fptrs->pLoadLibraryW = (LOADLIBRARYW)pGetProcAddress(hKernel32, buf19);
    if (!fptrs->pLoadLibraryW) {
        dprintf("ResolveOwnImports failed: LoadLibraryW");
        return FALSE;
    }

    char buf20[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\x00' };
    fptrs->pVirtualProtect = (VIRTUALPROTECT)pGetProcAddress(hKernel32, buf20);
    if (!fptrs->pVirtualProtect) {
        dprintf("ResolveOwnImports failed: VirtualProtect");
        return FALSE;
    }

    char buf21[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'W', '\x00' };
    fptrs->pGetModuleHandleW = (GETMODULEHANDLEW)pGetProcAddress(hKernel32, buf21);
    if (!fptrs->pGetModuleHandleW) {
        dprintf("ResolveOwnImports failed: GetModuleHandleW");
        return FALSE;
    }

    char buf22[] = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', '\x00' };
    fptrs->pOutputDebugStringA = (OUTPUTDEBUGSTR)pGetProcAddress(hKernel32, buf22);
    if (!fptrs->pOutputDebugStringA) {
        dprintf("ResolveOwnImports failed: OutputDebugStringA");
        return FALSE;
    }

    return TRUE;
}

BOOL RefreshPE(char* stomp, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress)
{
    HMODULE hModule;
    PWSTR wszFullDllName;
    PWSTR wszBaseDllName;
    ULONG_PTR pDllBase;

    PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

    struct FunctionPointers fptrs;

    for (unsigned int i = 0; i < sizeof(struct FunctionPointers); i++)
    {
        ((char*)&fptrs)[i] = 0;
    }

    if (!ResolveOwnImports(&fptrs, pLoadLibraryA, pGetProcAddress))
    {
        return FALSE;
    }

    size_t beaconDllLength = fptrs.pstrlen(stomp);

    dprintf("[REFRESH] Running DLLRefresher");

    pLdteHead = GetInMemoryOrderModuleList();
    pLdteCurrent = pLdteHead;

    do {
        if (pLdteCurrent->FullDllName.Length > 2 && !IsBeaconDLL(stomp, beaconDllLength, pLdteCurrent->BaseDllName.pBuffer, pLdteCurrent->BaseDllName.Length))
        {
            wszFullDllName = pLdteCurrent->FullDllName.pBuffer;
            wszBaseDllName = pLdteCurrent->BaseDllName.pBuffer;
            pDllBase = (ULONG_PTR)pLdteCurrent->DllBase;

            dprintf("[REFRESH] Refreshing DLL: %S", wszFullDllName);

            hModule = CustomLoadLibrary(&fptrs, wszFullDllName, wszBaseDllName, pDllBase);

            if (hModule)
            {
                ScanAndFixModule(&fptrs, (PCHAR)hModule, (PCHAR)pDllBase, wszBaseDllName);
                fptrs.pVirtualFree(hModule, 0, MEM_RELEASE);
            }
        }
        pLdteCurrent = (PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);

    return TRUE;
}

HMODULE CustomLoadLibrary(struct FunctionPointers* fptrs, const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase)
{
    // File handles
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    PCHAR pFile = NULL;

    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    // Library 
    PCHAR pLibraryAddr = NULL;
    DWORD dwIdx;

    // Relocation
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_BASE_RELOCATION pBaseReloc;
    ULONG_PTR pReloc;
    DWORD dwNumRelocs;
    ULONG_PTR pInitialImageBase;
    PIMAGE_RELOC pImageReloc;

    // Import
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PCHAR szDllName;
    SIZE_T stDllName;
    PWSTR wszDllName = NULL;
    PWCHAR wsRedir = NULL;
    PWSTR wszRedirName = NULL;
    SIZE_T stRedirName;
    SIZE_T stSize;

    HMODULE hModule;
    PIMAGE_THUNK_DATA pThunkData;
    FARPROC* pIatEntry;

    // clr.dll hotpatches itself at runtime for performance reasons, so skip it
    if (fptrs->pwcscmp(L"clr.dll", wszBaseDllName) == 0)
        goto cleanup;

    dprintf("[REFRESH] Opening file: %S", wszFullDllName);

    // ----
    // Step 1: Map the file into memory
    // ----

    hFile = fptrs->pCreateFileW(wszFullDllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto cleanup;

    hMap = fptrs->pCreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL)
        goto cleanup;

    pFile = (PCHAR)fptrs->pMapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (pFile == NULL)
        goto cleanup;

    // ----
    // Step 2: Parse the file headers and load it into memory
    // ----
    pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    pNtHeader = (PIMAGE_NT_HEADERS)(pFile + pDosHeader->e_lfanew);

    // allocate memory to copy DLL into
    dprintf("[REFRESH] Allocating memory for library");
    pLibraryAddr = (PCHAR)fptrs->pVirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy header
    dprintf("[REFRESH] Copying PE header into memory");
    __movsb((PBYTE)pLibraryAddr, (PBYTE)pFile, pNtHeader->OptionalHeader.SizeOfHeaders);

    // copy sections
    dprintf("[REFRESH] Copying PE sections into memory");
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pFile + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        __movsb((PBYTE)(pLibraryAddr + pSectionHeader[dwIdx].VirtualAddress),
            (PBYTE)(pFile + pSectionHeader[dwIdx].PointerToRawData),
            pSectionHeader[dwIdx].SizeOfRawData);
    }

    // update our pointers to the loaded image
    pDosHeader = (PIMAGE_DOS_HEADER)pLibraryAddr;
    pNtHeader = (PIMAGE_NT_HEADERS)(pLibraryAddr + pDosHeader->e_lfanew);

    // ----
    // Step 3: Calculate relocations
    // ----
    dprintf("[REFRESH] Calculating file relocations");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pInitialImageBase = pNtHeader->OptionalHeader.ImageBase;
    // set the ImageBase to the already loaded module's base
    pNtHeader->OptionalHeader.ImageBase = pDllBase;

    // check if their are any relocations present
    if (pDataDir->Size)
    {
        // calculate the address of the first IMAGE_BASE_RELOCATION entry
        pBaseReloc = (PIMAGE_BASE_RELOCATION)(pLibraryAddr + pDataDir->VirtualAddress);

        // iterate through each relocation entry
        while ((PCHAR)pBaseReloc < (pLibraryAddr + pDataDir->VirtualAddress + pDataDir->Size) && pBaseReloc->SizeOfBlock)
        {
            // the VA for this relocation block
            pReloc = (ULONG_PTR)(pLibraryAddr + pBaseReloc->VirtualAddress);

            // number of entries in this relocation block
            dwNumRelocs = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // first entry in the current relocation block
            pImageReloc = (PIMAGE_RELOC)((PCHAR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

            // iterate through each entry in the relocation block
            while (dwNumRelocs--)
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we subtract the initial ImageBase and add in the original dll base
                if (pImageReloc->type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR*)(pReloc + pImageReloc->offset) -= pInitialImageBase;
                    *(ULONG_PTR*)(pReloc + pImageReloc->offset) += pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *(DWORD*)(pReloc + pImageReloc->offset) -= (DWORD)pInitialImageBase;
                    *(DWORD*)(pReloc + pImageReloc->offset) += (DWORD)pDllBase;
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_HIGH)
                {
                    *(WORD*)(pReloc + pImageReloc->offset) -= HIWORD(pInitialImageBase);
                    *(WORD*)(pReloc + pImageReloc->offset) += HIWORD(pDllBase);
                }
                else if (pImageReloc->type == IMAGE_REL_BASED_LOW)
                {
                    *(WORD*)(pReloc + pImageReloc->offset) -= LOWORD(pInitialImageBase);
                    *(WORD*)(pReloc + pImageReloc->offset) += LOWORD(pDllBase);
                }

                // get the next entry in the current relocation block
                pImageReloc = (PIMAGE_RELOC)((PCHAR)pImageReloc + sizeof(IMAGE_RELOC));
            }

            // get the next entry in the relocation directory
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    }

    // ----
    // Step 4: Update import table
    // ----
    dprintf("[REFRESH] Resolving Import Address Table (IAT) ");

    pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pDataDir->Size)
    {
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pLibraryAddr + pDataDir->VirtualAddress);

        while (pImportDesc->Characteristics)
        {
            hModule = NULL;
            wszDllName = NULL;
            szDllName = (PCHAR)(pLibraryAddr + pImportDesc->Name);
            stDllName = fptrs->pstrnlen(szDllName, MAX_PATH);
            wszDllName = (PWSTR)fptrs->pcalloc(stDllName + 1, sizeof(WCHAR));

            if (wszDllName == NULL)
                goto next_import;

            fptrs->pmbstowcs_s(&stSize, wszDllName, stDllName + 1, szDllName, stDllName);

            dprintf("[REFRESH] Loading library: %S from %s", wszDllName, szDllName);

            // If the DLL starts with api- or ext-, resolve the redirected name and load it
            if (fptrs->p_wcsnicmp(wszDllName, L"api-", 4) == 0 || fptrs->p_wcsnicmp(wszDllName, L"ext-", 4) == 0)
            {
                // wsRedir is not null terminated
                wsRedir = GetRedirectedName(fptrs, wszBaseDllName, wszDllName, &stRedirName);
                if (wsRedir)
                {
                    // Free the original wszDllName and allocate a new buffer for the redirected dll name
                    fptrs->pfree(wszDllName);
                    wszDllName = (PWSTR)fptrs->pcalloc(stRedirName + 1, sizeof(WCHAR));
                    if (wszDllName == NULL)
                        goto next_import;

                    __movsb((PBYTE)wszDllName, (PBYTE)wsRedir, stRedirName * sizeof(WCHAR));
                    dprintf("[REFRESH] Redirected library: %S", wszDllName);
                }
            }

            // Load the module
            hModule = CustomGetModuleHandleW(fptrs, wszDllName);

            // Ignore libraries that fail to load
            if (hModule == NULL)
                goto next_import;

            if (pImportDesc->OriginalFirstThunk)
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->OriginalFirstThunk);
            else
                pThunkData = (PIMAGE_THUNK_DATA)(pLibraryAddr + pImportDesc->FirstThunk);

            pIatEntry = (FARPROC*)(pLibraryAddr + pImportDesc->FirstThunk);

            // loop through each thunk and resolve the import
            for (; DEREF(pThunkData); pThunkData++, pIatEntry++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
                    *pIatEntry = CustomGetProcAddressEx(fptrs, hModule, (PCHAR)IMAGE_ORDINAL(pThunkData->u1.Ordinal), wszDllName);
                else
                    *pIatEntry = CustomGetProcAddressEx(fptrs, hModule, ((PIMAGE_IMPORT_BY_NAME)(pLibraryAddr + DEREF(pThunkData)))->Name, wszDllName);
            }

        next_import:
            if (wszDllName != NULL)
            {
                fptrs->pfree(wszDllName);
                wszDllName = NULL;
            }
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pImportDesc + sizeof(IMAGE_IMPORT_DESCRIPTOR));

        }
    }

cleanup:
    if (pFile != NULL)
        fptrs->pUnmapViewOfFile(pFile);
    if (hMap != NULL)
        fptrs->pCloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE)
        fptrs->pCloseHandle(hFile);

    return (HMODULE)pLibraryAddr;
}

HMODULE CustomGetModuleHandleW(struct FunctionPointers* fptrs, const PWSTR wszModule)
{
    HMODULE hModule = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

    dprintf("[REFRESH] Searching for loaded module: %S", wszModule);

    pLdteCurrent = pLdteHead = GetInMemoryOrderModuleList();

    do {
        if (pLdteCurrent->FullDllName.Length > 2 &&
            fptrs->p_wcsnicmp(wszModule, pLdteCurrent->BaseDllName.pBuffer, pLdteCurrent->BaseDllName.Length / 2) == 0)
        {
            return ((HMODULE)pLdteCurrent->DllBase);
        }
        pLdteCurrent = (PLDR_DATA_TABLE_ENTRY)pLdteCurrent->InMemoryOrderModuleList.Flink;
    } while (pLdteCurrent != pLdteHead);

    return fptrs->pLoadLibraryW(wszModule);
}

VOID ScanAndFixModule(struct FunctionPointers* fptrs, PCHAR pKnown, PCHAR pSuspect, PWCHAR wszBaseDllName)
{
    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    DWORD dwIdx;

    dprintf("[REFRESH] Scanning module: %S", wszBaseDllName);

    pDosHeader = (PIMAGE_DOS_HEADER)pKnown;
    pNtHeader = (PIMAGE_NT_HEADERS)(pKnown + pDosHeader->e_lfanew);

    // Scan PE header
    ScanAndFixSection(fptrs, wszBaseDllName, "Header", pKnown, pSuspect, pNtHeader->OptionalHeader.SizeOfHeaders);

    // Scan each section
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pKnown + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        if (pSectionHeader[dwIdx].Characteristics & IMAGE_SCN_MEM_WRITE)
            continue;

        if (!((fptrs->pwcscmp(wszBaseDllName, L"clr.dll") == 0 && fptrs->pstrcmp((const char*)pSectionHeader[dwIdx].Name, ".text") == 0)))
        {
            ScanAndFixSection(fptrs, wszBaseDllName, (PCHAR)pSectionHeader[dwIdx].Name, pKnown + pSectionHeader[dwIdx].VirtualAddress,
                pSuspect + pSectionHeader[dwIdx].VirtualAddress, pSectionHeader[dwIdx].Misc.VirtualSize);
        }
    }
}

VOID ScanAndFixSection(struct FunctionPointers* fptrs, PWCHAR dll, PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength)
{
    DWORD ddOldProtect;

    if (fptrs->pmemcmp(pKnown, pSuspect, stLength) != 0)
    {
        if (!fptrs->pVirtualProtect(pSuspect, stLength, PAGE_EXECUTE_READWRITE, &ddOldProtect))
            return;

        dprintf("[REFRESH] Copying known good section into memory.");
        __movsb((PBYTE)pSuspect, (PBYTE)pKnown, stLength);

        if (!fptrs->pVirtualProtect(pSuspect, stLength, ddOldProtect, &ddOldProtect))
            dprintf("[REFRESH] Unable to reset memory permissions");
    }
}


// This code is modified from Stephen Fewer's GetProcAddress implementation
//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
FARPROC WINAPI CustomGetProcAddressEx(struct FunctionPointers* fptrs, HMODULE hModule, const PCHAR lpProcName, PWSTR wszOriginalModule)
{
    UINT_PTR uiLibraryAddress = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    UINT_PTR uiFuncVA = 0;
    PCHAR cpExportedFunctionName;
    PCHAR szFwdDesc;
    PCHAR szRedirFunc;
    PWSTR wszDllName;
    SIZE_T stDllName;
    PWCHAR wsRedir;
    PWSTR wszRedirName = NULL;
    SIZE_T stRedirName;

    HMODULE hFwdModule;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    FARPROC fpResult = NULL;
    DWORD dwCounter;

    if (hModule == NULL)
        return NULL;

    // a module handle is really its base address
    uiLibraryAddress = (UINT_PTR)hModule;

    // get the VA of the modules NT Header
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

    pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // get the VA of the export directory
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

    // get the VA for the array of addresses
    uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

    // get the VA for the array of name pointers
    uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

    // get the VA for the array of name ordinals
    uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

    // test if we are importing by name or by ordinal...
#pragma warning(suppress: 4311)
    if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
    {
        // import by ordinal...

        // use the import ordinal (- export ordinal base) as an index into the array of addresses
#pragma warning(suppress: 4311)
        uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

        // resolve the address for this imported function
        fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
    }
    else
    {
        // import by name...
        dwCounter = pExportDirectory->NumberOfNames;
        while (dwCounter--)
        {
            cpExportedFunctionName = (PCHAR)(uiLibraryAddress + DEREF_32(uiNameArray));

            // test if we have a match...
            if (fptrs->pstrcmp(cpExportedFunctionName, lpProcName) == 0)
            {
                // use the functions name ordinal as an index into the array of name pointers
                uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
                uiFuncVA = DEREF_32(uiAddressArray);

                // check for redirected exports
                if (pDataDirectory->VirtualAddress <= uiFuncVA && uiFuncVA < (pDataDirectory->VirtualAddress + pDataDirectory->Size))
                {
                    szFwdDesc = (PCHAR)(uiLibraryAddress + uiFuncVA);

                    // Find the first character after "."
                    szRedirFunc = (PCHAR)fptrs->pstrstr(szFwdDesc, ".") + 1;
                    stDllName = (SIZE_T)(szRedirFunc - szFwdDesc);

                    // Allocate enough space to append "dll"
                    wszDllName = (PWSTR)fptrs->pcalloc(stDllName + 3 + 1, sizeof(WCHAR));
                    if (wszDllName == NULL)
                        break;

                    fptrs->pmbstowcs_s(NULL, wszDllName, stDllName + 1, szFwdDesc, stDllName);
                    __movsb((PBYTE)(wszDllName + stDllName), (PBYTE)(L"dll"), 3 * sizeof(WCHAR));

                    // check for a redirected module name
                    if (fptrs->p_wcsnicmp(wszDllName, L"api-", 4) == 0 || fptrs->p_wcsnicmp(wszDllName, L"ext-", 4) == 0)
                    {
                        wsRedir = GetRedirectedName(fptrs, wszOriginalModule, wszDllName, &stRedirName);
                        if (wsRedir)
                        {
                            // Free the original buffer and allocate a new one for the redirected dll name
                            fptrs->pfree(wszDllName);

                            wszDllName = (PWSTR)fptrs->pcalloc(stRedirName + 1, sizeof(WCHAR));
                            if (wszDllName == NULL)
                                break;

                            __movsb((PBYTE)wszDllName, (PBYTE)wsRedir, stRedirName * sizeof(WCHAR));
                        }
                    }

                    hFwdModule = fptrs->pGetModuleHandleW(wszDllName);
                    fpResult = CustomGetProcAddressEx(fptrs, hFwdModule, szRedirFunc, wszDllName);
                    fptrs->pfree(wszDllName);
                }
                else
                {
                    // calculate the virtual address for the function
                    fpResult = (FARPROC)(uiLibraryAddress + uiFuncVA);
                }

                // finish...
                break;
            }

            // get the next exported function name
            uiNameArray += sizeof(DWORD);

            // get the next exported function name ordinal
            uiNameOrdinals += sizeof(WORD);
        }
    }

    return fpResult;
}


//===============================================================================================//

