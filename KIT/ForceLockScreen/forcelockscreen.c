#include <windows.h>
#include "forcelockscreen.h"
#include "beacon.h"

#pragma comment(lib, "User32.lib")

int go() {

    USER32$LockWorkStation();
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Lock screen forced for current user session.\n");
	
    return 0;
}


		
		
		
		