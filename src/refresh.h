#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "ReflectiveLoader.h"

#ifdef _DEBUG
#define OUTPUTDBGA(str) OutputDebugStringA(str);
#define OUTPUTDBGW(str) OutputDebugStringW(str);
#else
#define OUTPUTDBGA(str)
#define OUTPUTDBGW(str)
#endif


// Win 10
typedef struct _API_SET_VALUE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, * PAPI_SET_VALUE_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_HASH_ENTRY_V6
{
    ULONG Hash;
    ULONG Index;
} API_SET_NAMESPACE_HASH_ENTRY_V6, * PAPI_SET_NAMESPACE_HASH_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Size;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;
} API_SET_NAMESPACE_ENTRY_V6, * PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_ARRAY_V6
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG DataOffset;
    ULONG HashOffset;
    ULONG Multiplier;
    API_SET_NAMESPACE_ENTRY_V6 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V6, * PAPI_SET_NAMESPACE_ARRAY_V6;

// Windows 8.1
typedef struct _API_SET_VALUE_ENTRY_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V4, * PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4
{
    ULONG Flags;
    ULONG Count;
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, * PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V4, * PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, * PAPI_SET_NAMESPACE_ARRAY_V4;

// Windows 7/8
typedef struct _API_SET_VALUE_ENTRY_V2
{
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, * PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2
{
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, * PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2
{
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY_V2, * PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2
{
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, * PAPI_SET_NAMESPACE_ARRAY_V2;

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);



BOOL ResolveOwnImports(struct FunctionPointers* fptrs, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress);
BOOL RefreshPE(char* stomp, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress);
HMODULE CustomLoadLibrary(struct FunctionPointers* fptrs, const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase);
HMODULE CustomGetModuleHandleW(struct FunctionPointers* fptrs, const PWSTR wszModule);
FARPROC WINAPI CustomGetProcAddressEx(struct FunctionPointers* fptrs, HMODULE hModule, const PCHAR lpProcName, PWSTR wszOriginalModule);
VOID ScanAndFixModule(struct FunctionPointers* fptrs, PCHAR pKnown, PCHAR pSuspect, PWCHAR wszBaseDllName);
VOID ScanAndFixSection(struct FunctionPointers* fptrs, PWCHAR wszBaseDllName, PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength);

_PPEB GetProcessEnvironmentBlock();
PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList();


PWCHAR GetRedirectedName(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize);
PWCHAR GetRedirectedName_V6(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize);
PWCHAR GetRedirectedName_V4(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize);
PWCHAR GetRedirectedName_V2(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize);

