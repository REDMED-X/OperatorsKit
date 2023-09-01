#include <windows.h>  

//main
WINBASEAPI BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI void* WINAPI MSVCRT$strcpy(const char* dest, const char* source);
WINBASEAPI void* WINAPI MSVCRT$strcat(const char* dest, const char* source);
//DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* _Block);
DECLSPEC_IMPORT FILE* __cdecl MSVCRT$fopen(const char* _Filename, const char* _Mode);
DECLSPEC_IMPORT int __cdecl MSVCRT$fclose(FILE* _File);
DECLSPEC_IMPORT char* __cdecl MSVCRT$fgets(char* _Buffer, int _MaxCount, FILE* _File);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);
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
