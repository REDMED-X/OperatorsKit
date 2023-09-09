#include <Windows.h>
#include <stdio.h>
#include <wscapi.h>
#include <iwscapi.h>
#include "enumwsc.h"
#include "beacon.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wscapi.lib")


//START TrustedSec BOF print code: https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/base.c
#ifndef bufsize
#define bufsize 8192
#endif
char *output = 0;  
WORD currentoutsize = 0;
HANDLE trash = NULL; 
int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

int bofstart() {   
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args); 
    va_end(args);
    
    if (buffersize == -1) return;
    
    char* transferBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
	intBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args); 
    va_end(args);
    if(buffersize + currentoutsize < bufsize) 
    {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize) 
            {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if(currentoutsize == bufsize)
            {
                printoutput(FALSE); 
            }
            MSVCRT$memset(transferBuffer, 0, transfersize); 
            curloc += transfersize; 
            buffersize -= transfersize;
        }
    }
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, intBuffer);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, transferBuffer);
}

void printoutput(BOOL done) {
    char * msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
//END TrustedSec BOF print code.


HRESULT GetSecurityProducts(WSC_SECURITY_PROVIDER provider) {
    HRESULT hr;
    IWscProduct* PtrProduct = NULL;
    IWSCProductList* PtrProductList = NULL;
    BSTR PtrVal = NULL;
    LONG ProductCount = 0;
    WSC_SECURITY_PRODUCT_STATE ProductState;
    WSC_SECURITY_SIGNATURE_STATUS ProductStatus;

    if (provider != WSC_SECURITY_PROVIDER_FIREWALL &&
        provider != WSC_SECURITY_PROVIDER_ANTIVIRUS &&
        provider != WSC_SECURITY_PROVIDER_ANTISPYWARE) {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
	
    hr = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) goto Cleanup;

    IID CLSIDWSCProductList = {0x17072f7b, 0x9abe, 0x4a74, {0xa2, 0x61, 0x1e, 0xb7, 0x6b, 0x55, 0x10, 0x7a}};
    IID IIDIWSCProductList = {0x722a338c, 0x6e8e, 0x4e72, {0xac, 0x27, 0x14, 0x17, 0xfb, 0x0c, 0x81, 0xc2}};
    hr = OLE32$CoCreateInstance(&CLSIDWSCProductList, NULL, CLSCTX_INPROC_SERVER, &IIDIWSCProductList, (LPVOID*)&PtrProductList);
    if (FAILED(hr)) {
        if (hr == 0x80040154) {
            BeaconPrintf(CALLBACK_ERROR, "Windows Security Center is not running on this system.");
        } 
        goto Cleanup;
    }
	
	if (provider == WSC_SECURITY_PROVIDER_ANTIVIRUS) internal_printf("\nFound registered antivirus product(s) in WSC:\n====================================================\n");
	else if (provider == WSC_SECURITY_PROVIDER_FIREWALL) internal_printf("\nFound registered firewall product(s) in WSC:\n====================================================\n");
	else internal_printf("\nFound registered antispyware product(s) in WSC:\n====================================================\n");
	

    hr = PtrProductList->lpVtbl->Initialize(PtrProductList, provider);
    if (FAILED(hr)) goto Cleanup;

    hr = PtrProductList->lpVtbl->get_Count(PtrProductList, &ProductCount);
    if (FAILED(hr)) goto Cleanup;

    for (LONG i = 0; i < ProductCount; i++) {
        hr = PtrProductList->lpVtbl->get_Item(PtrProductList, i, &PtrProduct);
        if (FAILED(hr)) goto Cleanup;

        hr = PtrProduct->lpVtbl->get_ProductName(PtrProduct, &PtrVal);
        if (FAILED(hr)) goto Cleanup;

        internal_printf("%ls\n", PtrVal);
        OLEAUT32$SysFreeString(PtrVal);
        PtrVal = NULL;

        hr = PtrProduct->lpVtbl->get_ProductState(PtrProduct, &ProductState);
        if (FAILED(hr)) goto Cleanup;

        const char* pszState;
        if (ProductState == WSC_SECURITY_PRODUCT_STATE_ON) {
            pszState = "On";
        } else if (ProductState == WSC_SECURITY_PRODUCT_STATE_OFF) {
            pszState = "Off";
        } else if (ProductState == WSC_SECURITY_PRODUCT_STATE_SNOOZED) {
            pszState = "Snoozed";
        } else {
            pszState = "Expired";
        }
        internal_printf("- Product state: %s\n", pszState);

        hr = PtrProduct->lpVtbl->get_SignatureStatus(PtrProduct, &ProductStatus);
        if (FAILED(hr)) goto Cleanup;

        const char* pszStatus = (ProductStatus == WSC_SECURITY_PRODUCT_UP_TO_DATE) ? "Up-to-date" : "Out-of-date";
        internal_printf("- Product status: %s\n", pszStatus);

        PtrProduct->lpVtbl->Release(PtrProduct);
        PtrProduct = NULL;
		
		internal_printf("----------------------------------------------------\n\n");
    }

Cleanup:
    if (PtrVal) OLEAUT32$SysFreeString(PtrVal);
    if (PtrProductList) PtrProductList->lpVtbl->Release(PtrProductList);
    if (PtrProduct) PtrProduct->lpVtbl->Release(PtrProduct);
    OLE32$CoUninitialize();

    return hr;
}

int go(char *args, int len) {
	HRESULT hr;
	CHAR* option = "";
    datap parser;
	
    BeaconDataParse(&parser, args, len);
    option = BeaconDataExtract(&parser, NULL);
	if(!bofstart()) return;
	
	if (MSVCRT$strcmp(option, "av") == 0) hr = GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTIVIRUS);
	else if (MSVCRT$strcmp(option, "fw") == 0) hr = GetSecurityProducts(WSC_SECURITY_PROVIDER_FIREWALL);
	else if (MSVCRT$strcmp(option, "as") == 0) hr = GetSecurityProducts(WSC_SECURITY_PROVIDER_ANTISPYWARE);
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please specify one of following options: av | fw | as\n");
		return 0;
	}
	
    if (SUCCEEDED(hr)) {
        printoutput(TRUE);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enumerate security products from WSC.\n");
    }

    return 0;
}