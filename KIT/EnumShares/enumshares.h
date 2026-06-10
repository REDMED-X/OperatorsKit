#include <windows.h>
#include <Lm.h>

// --- KERNEL32 ---
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI void    WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI DWORD   WINAPI KERNEL32$GetTickCount(VOID);
WINBASEAPI DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
WINBASEAPI int     WINAPI KERNEL32$lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

// --- MSVCRT ---
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void    __cdecl MSVCRT$free(void * _Memory);
WINBASEAPI void* __cdecl MSVCRT$memset(void * _Dst, int _Val, size_t _Size);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void * _Dst, const void * _Src, size_t _MaxCount);
WINBASEAPI int     __cdecl MSVCRT$vsnprintf(char * _Dest, size_t _Count, const char * _Format, va_list _Args);
WINBASEAPI int     __cdecl MSVCRT$_snwprintf(wchar_t * _Dest, size_t _Count, const wchar_t * _Format, ...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char * _Str, const char * _Delim);
WINBASEAPI int     __cdecl MSVCRT$rand(void);
WINBASEAPI void    __cdecl MSVCRT$srand(unsigned int _Seed);

// --- NETAPI32 ---
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetShareEnum(LMSTR servername, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resume_handle);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(LPVOID Buffer);

// --- WS2_32 ---
DECLSPEC_IMPORT int    WINAPI WS2_32$WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int    WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int    WINAPI WS2_32$getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const struct addrinfo *pHints, struct addrinfo **ppResult);
DECLSPEC_IMPORT void   WINAPI WS2_32$freeaddrinfo(struct addrinfo *pAddrInfo);
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int    WINAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT int    WINAPI WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);
DECLSPEC_IMPORT int    WINAPI WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int    WINAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT int    WINAPI WS2_32$select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);