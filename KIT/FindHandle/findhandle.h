#include <windows.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
 
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
 
#define QUERY_PROC		0x08
#define QUERY_THREAD	0x10


//GetHandles
typedef NTSTATUS (NTAPI * NtQuerySystemInformation_t)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS (NTAPI * NtDuplicateObject_t)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);
typedef NTSTATUS (NTAPI * NtQueryObject_t)(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t _Size);
WINBASEAPI void* __cdecl MSVCRT$realloc(void* _Memory, size_t _NewSize);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$K32GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$StrStrIW(LPCWSTR lpFirst, LPCWSTR lpSrch);
DECLSPEC_IMPORT PCWSTR WINAPI SHLWAPI$StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch);
//WINBASEAPI void __cdecl MSVCRT$free(void* _Memory);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetProcessId(HANDLE Process);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetProcessIdOfThread(HANDLE Thread);
WINBASEAPI int __cdecl MSVCRT$sprintf_s(char *_Dst,size_t _SizeInBytes,const char *_Format,...);
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *_Dst,size_t _SizeInWords,const wchar_t *_Format,...);
DECLSPEC_IMPORT LPCSTR WINAPI SHLWAPI$PathFindFileNameA(LPCSTR pszPath);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...); 
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);

//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
 
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
 
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
 
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

