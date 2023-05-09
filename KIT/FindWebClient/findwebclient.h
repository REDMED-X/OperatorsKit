#include <windows.h>  

//main
WINBASEAPI BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI void* WINAPI MSVCRT$strcpy(const char* dest, const char* source);
WINBASEAPI void* WINAPI MSVCRT$strcat(const char* dest, const char* source);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* _Block);
DECLSPEC_IMPORT FILE* __cdecl MSVCRT$fopen(const char* _Filename, const char* _Mode);
DECLSPEC_IMPORT int __cdecl MSVCRT$fclose(FILE* _File);
DECLSPEC_IMPORT char* __cdecl MSVCRT$fgets(char* _Buffer, int _MaxCount, FILE* _File);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);

//BeaconPrintToStreamW + BeaconOutputStreamW
#define MAX_STRING 8192
INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
//WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);




