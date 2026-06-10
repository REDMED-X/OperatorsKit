#include <windows.h>
#include <winnt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "beacon.h"
#include "enumdllsideloading.h"

// ============================================================================
// TrustedSec BOF output buffering logic
// Purpose: Batch up printed output into a buffer to avoid Beacon print spam.
// ============================================================================
#ifndef bufsize
#define bufsize 8192
#endif
char *output = 0;                 
WORD currentoutsize = 0;          
HANDLE trash = NULL;              

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

// Initializes output buffer for this BOF run
int bofstart() {
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

// Formats text like printf, appends to output buffer, flushes if full
void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;

    // First pass: measure formatted string size
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1) return;

    // Allocate temp buffers
    char* transferBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    intBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);

    // Second pass: actually format string into intBuffer
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);

    // Append to output buffer (with flush logic)
    if(buffersize + currentoutsize < bufsize) {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while(buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize) {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;

            // Flush if buffer is full
            if(currentoutsize == bufsize) {
                printoutput(FALSE);
            }
            MSVCRT$memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }

    // Free temp buffers
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, intBuffer);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, transferBuffer);
}

// Sends buffer to Beacon and optionally frees it
void printoutput(BOOL done) {
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}

// ============================================================================
// NTDLL resolver: loads low-level NT APIs for KnownDLL detection
// ============================================================================
static PFN_NtOpenSection        pNtOpenSection = NULL;
static PFN_RtlInitUnicodeString pRtlInitUnicodeString = NULL;

// Ensures function pointers for NtOpenSection / RtlInitUnicodeString are loaded
static void ensure_ntdll(void) {
    if (pNtOpenSection && pRtlInitUnicodeString) return;
    HMODULE hNt = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (!hNt) hNt = KERNEL32$LoadLibraryW(L"ntdll.dll");
    if (!hNt) return;
    pNtOpenSection = (PFN_NtOpenSection)KERNEL32$GetProcAddress(hNt, "NtOpenSection");
    pRtlInitUnicodeString = (PFN_RtlInitUnicodeString)KERNEL32$GetProcAddress(hNt, "RtlInitUnicodeString");
}

// ============================================================================
// Minimal libc-style helpers (avoid linking standard libs in BOF)
// ============================================================================
static size_t c_strlen(const char* s) { return MSVCRT$strlen(s); }
static void c_strcpy(char* dst, const char* src) { size_t n = MSVCRT$strlen(src) + 1; MSVCRT$memcpy(dst, src, n); }
static void c_strcat(char* dst, const char* src) { size_t d = MSVCRT$strlen(dst), s = MSVCRT$strlen(src); MSVCRT$memcpy(dst + d, src, s + 1); }

// Case-insensitive compare
static int c_stricmp(const char* a, const char* b) {
    while (*a && *b) {
        int ca = MSVCRT$toupper((unsigned char)*a++);
        int cb = MSVCRT$toupper((unsigned char)*b++);
        if (ca != cb) return (ca - cb);
    }
    return ((unsigned char)*a) - ((unsigned char)*b);
}

// Case-insensitive substring search
static char* c_stristr(const char* hay, const char* needle) {
    if (!*needle) return (char*)hay;
    size_t nlen = c_strlen(needle);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (i < nlen) {
            char a = (char)MSVCRT$toupper((unsigned char)p[i]);
            char b = (char)MSVCRT$toupper((unsigned char)needle[i]);
            if (a != b) break;
            ++i;
        }
        if (i == nlen) return (char*)p;
    }
    return NULL;
}

// Extract filename from path
static const char* path_find_filename(const char* path) {
    const char* last = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '/') last = p + 1;
    }
    return last;
}

// Extract file extension (or end if none)
static const char* path_find_extension(const char* path) {
    const char* fn = path_find_filename(path);
    const char* dot = NULL;
    for (const char* p = fn; *p; ++p) {
        if (*p == '.') dot = p;
    }
    return dot ? dot : fn + c_strlen(fn);
}

// Get directory portion of a path
static void dir_from_path(const char* full, char* out, DWORD outsz) {
    size_t n = c_strlen(full);
    if (n + 1 > outsz) n = outsz - 1;
    MSVCRT$memcpy(out, full, n); out[n] = 0;
    for (intptr_t i = (intptr_t)n - 1; i >= 0; --i) {
        if (out[i] == '\\' || out[i] == '/') { out[i] = 0; break; }
    }
}

// Join directory and filename into dst
static void join_path(char *dst, DWORD dstsz, const char *dir, const char *name) {
    dst[0] = 0;
    size_t dl = c_strlen(dir), nl = c_strlen(name);
    if (dl + 1 + nl + 1 >= dstsz) return;
    c_strcpy(dst, dir);
    if (dl && dir[dl-1] != '\\' && dir[dl-1] != '/') c_strcat(dst, "\\");
    c_strcat(dst, name);
}

// Uppercase basename from path
static void basename_upper(const char* path, char* out, DWORD outsz) {
    const char* b = path_find_filename(path);
    size_t n = c_strlen(b); if (n + 1 > outsz) n = outsz - 1;
    MSVCRT$memcpy(out, b, n); out[n] = 0;
    for (size_t i = 0; out[i]; ++i) out[i] = (char)MSVCRT$toupper((unsigned char)out[i]);
}

// ============================================================================
// DLL classification helpers
// ============================================================================
static bool is_api_set(const char* nameUpper) {
    return (c_stristr(nameUpper, "API-MS-WIN-") == nameUpper) ||
           (c_stristr(nameUpper, "EXT-MS-")     == nameUpper);
}

static bool is_winsxs_path(const char* p) {
    return c_stristr(p, "\\WINDOWS\\WINSXS\\") != NULL ||
           c_stristr(p, "\\WINNT\\WINSXS\\")   != NULL;
}

// Check if DLL is in KnownDlls via NtOpenSection
static bool is_known_dll_by_nt(const char* dllBaseUpper) {
    ensure_ntdll();
    if (!pNtOpenSection || !pRtlInitUnicodeString) return false;
    wchar_t wName[260];
    int n = KERNEL32$MultiByteToWideChar(CP_ACP, 0, dllBaseUpper, -1, wName, 260);
    if (n <= 0) return false;

    const wchar_t* roots[2] = { L"\\KnownDlls\\", L"\\KnownDlls32\\" };
    for (int i = 0; i < 2; ++i) {
        wchar_t full[320];
        int pos = 0;
        for (const wchar_t* rp = roots[i]; *rp && pos < 319; ++rp) full[pos++] = *rp;
        for (const wchar_t* wp = wName; *wp && pos < 319; ++wp) full[pos++] = *wp;
        full[pos] = 0;

        UNICODE_STRING us;
        OBJECT_ATTRIBUTES oa;
        HANDLE hSec = NULL;
        pRtlInitUnicodeString(&us, full);
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NTSTATUS st = pNtOpenSection(&hSec, SECTION_MAP_READ, &oa);
        if (st == STATUS_SUCCESS && hSec) { KERNEL32$CloseHandle(hSec); return true; }
    }
    return false;
}

// ============================================================================
// PE parsing helpers
// ============================================================================
#if !defined(IMAGE_FIRST_SECTION)
#define IMAGE_FIRST_SECTION(nt) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(&((nt)->OptionalHeader)) + (nt)->FileHeader.SizeOfOptionalHeader))
#endif

#if defined(_WIN64)
  #define IMAGE_NT_HEADERS_T IMAGE_NT_HEADERS64
#else
  #define IMAGE_NT_HEADERS_T IMAGE_NT_HEADERS32
#endif

static PIMAGE_SECTION_HEADER FirstSection(IMAGE_NT_HEADERS_T* nt) {
    return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt);
}

// Convert Relative Virtual Address (RVA) to file offset
static DWORD RvaToOffset(DWORD rva, IMAGE_NT_HEADERS_T* nt) {
    PIMAGE_SECTION_HEADER sec = FirstSection(nt);
    WORD c = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < c; ++i, ++sec) {
        DWORD start = sec->VirtualAddress;
        DWORD end   = start + (sec->SizeOfRawData > sec->Misc.VirtualSize ? sec->SizeOfRawData : sec->Misc.VirtualSize);
        if (rva >= start && rva < end) {
            return (rva - start) + sec->PointerToRawData;
        }
    }
    if (rva < nt->OptionalHeader.SizeOfHeaders) return rva;
    return 0;
}

// Convert RVA to in-buffer string pointer
static const char* RvaToPtrStr(DWORD rva, IMAGE_NT_HEADERS_T* nt, BYTE* base, DWORD fileSize) {
    DWORD off = RvaToOffset(rva, nt);
    if (!off || off >= fileSize) return NULL;
    return (const char*)(base + off);
}

// ============================================================================
// DLL classification: determine if a DLL is sideloadable or not
// ============================================================================
static void ReportLine(const char* status, const char* dll, const char* detail) {
    internal_printf("%-10s\t | %-16s\t | %s\n", status, dll, detail);
}

static void ClassifyDll(const char* dllName, const char* exeDirA) {
    // Skip invalid or empty DLL names
    if (!dllName || !*dllName) return;

    // Only consider ".DLL" files if extension exists
    const char* ext = path_find_extension(dllName);
    if (*ext != 0) {
        if (c_stricmp(ext, ".DLL") != 0) return; // skip other
    }

    // Skip absolute paths (only relative DLLs are interesting for sideloading)
    if (dllName[0] == '\\' || dllName[1] == ':') return;

    // Convert DLL name to uppercase for consistent comparison
    char baseUpper[MAX_PATH];
    basename_upper(dllName, baseUpper, MAX_PATH);

    // Skip API set DLLs and KnownDLLs
    if (is_api_set(baseUpper)) return;
    if (is_known_dll_by_nt(baseUpper)) return;

    // Build local path using uppercase DLL name
    char localA[MAX_PATH]; localA[0] = 0;
    size_t dl = c_strlen(exeDirA);
    size_t nl = c_strlen(baseUpper);
    if (dl + 1 + nl + 1 < MAX_PATH) {
        c_strcpy(localA, exeDirA);
        c_strcat(localA, "\\");
        c_strcat(localA, baseUpper);
    }

    // Build local path using original DLL name
    char localOrig[MAX_PATH]; localOrig[0] = 0;
    size_t no = c_strlen(dllName);
    if (dl + 1 + no + 1 < MAX_PATH) {
        c_strcpy(localOrig, exeDirA);
        c_strcat(localOrig, "\\");
        c_strcat(localOrig, dllName);
    }

    // Check if DLL exists in local folder
    bool existsLocal = false, existsLocalOrig = false;
    HANDLE hf;
    if (localA[0]) {
        hf = KERNEL32$CreateFileA(localA, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) { existsLocal = true; KERNEL32$CloseHandle(hf); }
    }
    if (localOrig[0]) {
        hf = KERNEL32$CreateFileA(localOrig, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) { existsLocalOrig = true; KERNEL32$CloseHandle(hf); }
    }

    // If found locally, it's not sideloadable
    if (existsLocal || existsLocalOrig) {
        ReportLine("[-] No", baseUpper, existsLocalOrig ? localOrig : localA);
        return;
    }

    // Otherwise, resolve via SearchPath to see where Windows would load it from
    char resolved[MAX_PATH]; resolved[0] = 0;
    DWORD len = KERNEL32$SearchPathA(NULL, dllName, NULL, MAX_PATH, resolved, NULL);
    if (len && len < MAX_PATH) {
        if (is_winsxs_path(resolved)) return; // Skip Side-by-Side assemblies (WinSxS) system-bound DLLs
        ReportLine("[+] Yes!", baseUpper, resolved);
    } else {
        // DLL not found anywhere — could be sideloaded with non-proxy DLL
        ReportLine("[+] Yes!", baseUpper, "[!] Missing entirely (no proxy dll required)");
    }
}

// ============================================================================
// Import walkers: iterate over the import tables of a PE file
// ============================================================================
static void ProcessNormalImports(BYTE* base, DWORD fileSize, IMAGE_NT_HEADERS_T* nt, const char* exeDirA) {
    // Handles IMAGE_DIRECTORY_ENTRY_IMPORT (normal DLL imports)
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;

    DWORD off = RvaToOffset(dir.VirtualAddress, nt);
    if (!off || off >= fileSize) return;

    // Iterate over each import descriptor
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + off);
    for (; imp->Name; ++imp) {
        const char* dllName = RvaToPtrStr(imp->Name, nt, base, fileSize);
        if (!dllName) continue;
        ClassifyDll(dllName, exeDirA);
    }
}

static void ProcessDelayImports(BYTE* base, DWORD fileSize, IMAGE_NT_HEADERS_T* nt, const char* exeDirA) {
    // Handles IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (delay-loaded DLLs)
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;

    DWORD off = RvaToOffset(dir.VirtualAddress, nt);
    if (!off || off >= fileSize) return;

    // Iterate over each delay-load descriptor
    PIMAGE_DELAYLOAD_DESCRIPTOR d = (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + off);
    for (; d->DllNameRVA; ++d) {
        const char* dllName = RvaToPtrStr(d->DllNameRVA, nt, base, fileSize);
        if (!dllName) continue;
        ClassifyDll(dllName, exeDirA);
    }
}

// ============================================================================
// Main PE analysis for sideloading
// ============================================================================
static void AnalyzeSideloading(const char* exePathA) {
    char exeFullA[MAX_PATH]; exeFullA[0] = 0;
    // Get absolute path to EXE
    DWORD n = KERNEL32$GetFullPathNameA(exePathA, MAX_PATH, exeFullA, NULL);
    if (!n || n >= MAX_PATH) { BeaconPrintf(CALLBACK_ERROR, "Error resolving path: %s\n", exePathA); return; }

    // Extract directory part of EXE path
    char exeDirA[MAX_PATH]; dir_from_path(exeFullA, exeDirA, MAX_PATH);

    // Open EXE for reading
    HANDLE hf = KERNEL32$CreateFileA(exeFullA, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_ERROR, "CreateFile failed (%lu)\n", KERNEL32$GetLastError()); return; }

    // Get file size
    LARGE_INTEGER sz;
    if (!KERNEL32$GetFileSizeEx(hf, &sz) || sz.HighPart) {
        BeaconPrintf(CALLBACK_ERROR, "Bad/large file size\n");
        KERNEL32$CloseHandle(hf);
        return;
    }
    DWORD fsz = sz.LowPart;

    // Allocate buffer and read file into memory
    BYTE* base = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, fsz);
    if (!base) { BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed\n"); KERNEL32$CloseHandle(hf); return; }
    DWORD rd = 0;
    if (!KERNEL32$ReadFile(hf, base, fsz, &rd, NULL) || rd != fsz) {
        BeaconPrintf(CALLBACK_ERROR, "ReadFile failed (%lu)\n", KERNEL32$GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, base);
        KERNEL32$CloseHandle(hf);
        return;
    }
    KERNEL32$CloseHandle(hf);

    // Verify DOS header
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Not a valid MZ/PE file\n");
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, base);
        return;
    }

    // Verify NT headers
    DWORD ntOff = (DWORD)dos->e_lfanew;
    if (ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) >= fsz) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid NT headers offset\n");
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, base);
        return;
    }
    if (*(DWORD*)(base + ntOff) != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Missing PE signature\n");
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, base);
        return;
    }

    // Cast NT headers
    IMAGE_NT_HEADERS_T* nt = (IMAGE_NT_HEADERS_T*)(base + ntOff);

    // Print table header
    internal_printf("Sideloadable?\t | DLL name\t\t | DLL real path\n");
    internal_printf("--------------------------------------------------------------------------------------------------------------------------------\n");

    // Process normal and delay imports
    ProcessNormalImports(base, fsz, nt, exeDirA);
    ProcessDelayImports(base, fsz, nt, exeDirA);

    // Cleanup
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, base);
}

// ============================================================================
// Directory scanning
// ============================================================================
static void ScanDirectory(const char *baseDir, bool recursive) {
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;
    char pattern[MAX_PATH];
    char full[MAX_PATH];

    // Pass 1: Find all EXE files in directory
    join_path(pattern, MAX_PATH, baseDir, "*.exe");
    hFind = KERNEL32$FindFirstFileA(pattern, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                join_path(full, MAX_PATH, baseDir, ffd.cFileName);
                internal_printf("\n\n================================================================================================================================\n");
                internal_printf("[*] Enumerating .EXE: %s\n", full);
                internal_printf("--------------------------------------------------------------------------------------------------------------------------------\n");
                AnalyzeSideloading(full);
            }
        } while (KERNEL32$FindNextFileA(hFind, &ffd));
        KERNEL32$FindClose(hFind);
    }

    // Pass 2: If recursive, scan subdirectories
    if (recursive) {
        join_path(pattern, MAX_PATH, baseDir, "*");
        hFind = KERNEL32$FindFirstFileA(pattern, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    c_stricmp(ffd.cFileName, ".") != 0 &&
                    c_stricmp(ffd.cFileName, "..") != 0) {
                    join_path(full, MAX_PATH, baseDir, ffd.cFileName);
                    ScanDirectory(full, true);
                }
            } while (KERNEL32$FindNextFileA(hFind, &ffd));
            KERNEL32$FindClose(hFind);
        }
    }
}

// Decide base directory (from EXE path or CWD)
static void ChooseBaseDirectory(char *outDir, DWORD outSz, const char *firstArgPath) {
    outDir[0] = 0;
    if (firstArgPath && *firstArgPath) {
        char full[MAX_PATH]; full[0] = 0;
        DWORD n = KERNEL32$GetFullPathNameA(firstArgPath, MAX_PATH, full, NULL);
        if (n && n < MAX_PATH) {
            dir_from_path(full, outDir, outSz);
            if (*outDir) return;
        }
    }
    KERNEL32$GetCurrentDirectoryA(outSz, outDir);
}

// ============================================================================
// Entry point
// ============================================================================
int go(char *args, int len) {
    datap parser;
    CHAR *exePath = "";
    CHAR *mode = "single"; // Mode: "single", "folder", or "recursive"

    BeaconDataParse(&parser, args, len);
    exePath = (CHAR*)BeaconDataExtract(&parser, NULL);
    mode    = (CHAR*)BeaconDataExtract(&parser, NULL);

    if(!bofstart()) return 0;

    if (mode && *mode && (c_stricmp(mode, "folder") == 0 || c_stricmp(mode, "recursive") == 0)) {
        char baseDir[MAX_PATH];
        bool rec = (c_stricmp(mode, "recursive") == 0);
        ChooseBaseDirectory(baseDir, MAX_PATH, exePath);
        if (!*baseDir) {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine base directory.\n");
            return 0;
        }
        ScanDirectory(baseDir, rec);
    }

    else if (mode && *mode && (c_stricmp(mode, "single") == 0)) {
        AnalyzeSideloading(exePath);
    }

    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command! Specify one of the following commands: single, folder, recursive\n");
        return 1;
    }

    printoutput(TRUE);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
    return 0;
}
