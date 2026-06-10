#include <windows.h>  

//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

//enumactivehosts
WINBASEAPI int __cdecl MSVCRT$atoi(const char *str);
WINBASEAPI int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
WINBASEAPI int WSAAPI WS2_32$WSACleanup(void);
WINBASEAPI int WSAAPI WS2_32$WSAGetLastError(void);
WINBASEAPI INT WSAAPI WS2_32$getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
WINBASEAPI void WSAAPI WS2_32$freeaddrinfo(PADDRINFOA pAddrInfo);
WINBASEAPI SOCKET WSAAPI WS2_32$socket(int af, int type, int protocol);
WINBASEAPI int WSAAPI WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);
WINBASEAPI int WSAAPI WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
WINBASEAPI int WSAAPI WS2_32$closesocket(SOCKET s);
WINBASEAPI int WSAAPI WS2_32$select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
WINBASEAPI int WSAAPI WS2_32$getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);