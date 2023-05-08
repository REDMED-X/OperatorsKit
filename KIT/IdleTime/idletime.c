#include <stdio.h>
#include <windows.h>
#include "idletime.h"
#include "beacon.h"

#pragma comment(lib, "User32.lib")


DWORD GetIdleTimeInSeconds() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    USER32$GetLastInputInfo(&lii);

    DWORD currentTime = KERNEL32$GetTickCount();
    DWORD lastInputTime = lii.dwTime;

    return (currentTime - lastInputTime) / 1000;
}

void FormatIdleTime(DWORD idleTime, int *hours, int *minutes, int *seconds) {
    *hours = idleTime / 3600;
    *minutes = (idleTime % 3600) / 60;
    *seconds = idleTime % 60;
}


int go() {
    DWORD idleTime = GetIdleTimeInSeconds();
	
	int hours, minutes, seconds;
    FormatIdleTime(idleTime, &hours, &minutes, &seconds);
	
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Last user input was observed %02d:%02d:%02d ago.\n", hours, minutes, seconds);
    return 0;
}