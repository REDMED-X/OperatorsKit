#include <windows.h>

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;				// absolute system, number of 100-nanosecond intervals 
	LARGE_INTEGER LastAccessTime;			// since the start of the year 1601 in the Gregorian calendar.
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;					// metadata about the file, ex.: archive, compressed, directory, hidden, etc.
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;


typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation                         = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55
    FileRenameInformationBypassAccessCheck,         // 56
    FileLinkInformationBypassAccessCheck,           // 57
    FileVolumeNameInformation,                      // 58
    FileIdInformation,                              // 59
    FileIdExtdDirectoryInformation,                 // 60
    FileReplaceCompletionInformation,               // 61
    FileHardLinkFullIdInformation,                  // 62
    FileIdExtdBothDirectoryInformation,             // 63
    FileDispositionInformationEx,                   // 64
    FileRenameInformationEx,                        // 65
    FileRenameInformationExBypassAccessCheck,       // 66
    FileDesiredStorageClassInformation,             // 67
    FileStatInformation,                            // 68
    FileMemoryPartitionInformation,                 // 69
    FileStatLxInformation,                          // 70
    FileCaseSensitiveInformation,                   // 71
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75
    FileKnownFolderInformation,   					// 76
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(
  HANDLE                 FileHandle,
  PIO_STATUS_BLOCK       IoStatusBlock,
  PVOID                  FileInformation,
  ULONG                  Length,
  FILE_INFORMATION_CLASS FileInformationClass
);


typedef NTSTATUS (NTAPI *NtSetInformationFile_t)(
  HANDLE                 FileHandle,
  PIO_STATUS_BLOCK       IoStatusBlock,
  PVOID                  FileInformation,
  ULONG                  Length,
  FILE_INFORMATION_CLASS FileInformationClass
);

//CreateHiddenDir
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...); 
WINBASEAPI int __cdecl MSVCRT$getchar(void); 

//CreateHiddenFile
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);

//MoveDLL
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);

//RunProc
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
DECLSPEC_IMPORT void WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);

//main
WINBASEAPI wchar_t * __cdecl MSVCRT$wcscpy(wchar_t *destination, const wchar_t *source);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcscat(wchar_t *destination, const wchar_t *source);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char *destination, const char *source);
WINBASEAPI char * __cdecl MSVCRT$strcat(char *destination, const char *source);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *string);

