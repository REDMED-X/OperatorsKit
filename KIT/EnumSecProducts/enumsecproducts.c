#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <wtsapi32.h>
#include "enumsecproducts.h"
#include "beacon.h"


typedef struct {
    const char *filename;
    const char *description;
    const char *category;
} SoftwareData;


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




void go(char *args, int len) {
	CHAR *hostName = "";
	HANDLE handleHost = NULL;
    datap parser;
	DWORD argSize = NULL;
	WTS_PROCESS_INFOA * proc_info;
	DWORD pi_count = 0;
	LPSTR procName; 
	bool foundSecProduct = false;
	
    BeaconDataParse(&parser, args, len);
    hostName = BeaconDataExtract(&parser, &argSize);
	if(!bofstart()) return;

	//allocate memory for list
	size_t numSoftware = 130; //130
    SoftwareData *softwareList = (SoftwareData *)KERNEL32$VirtualAlloc(NULL, numSoftware * sizeof(SoftwareData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (softwareList == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for softwareList.\n");
        return -1;
    }

    //Start security product list
	softwareList[0].filename = "avastsvc.exe";
	softwareList[0].description = L"Avast";
	softwareList[0].category = L"AV";

	softwareList[1].filename = "avastui.exe";
	softwareList[1].description = L"Avast";
	softwareList[1].category = L"AV";

	softwareList[2].filename = "avgnt.exe";
	softwareList[2].description = L"Avira";
	softwareList[2].category = L"AV";

	softwareList[3].filename = "avguard.exe";
	softwareList[3].description = L"Avira";
	softwareList[3].category = L"AV";

	softwareList[4].filename = "avp.exe";
	softwareList[4].description = L"Kaspersky";
	softwareList[4].category = L"AV";

	softwareList[5].filename = "axcrypt.exe";
	softwareList[5].description = L"AxCrypt";
	softwareList[5].category = L"Encryption";

	softwareList[6].filename = "bdagent.exe";
	softwareList[6].description = L"Bitdefender Total Security";
	softwareList[6].category = L"AV";

	softwareList[7].filename = "carbonsensor.exe";
	softwareList[7].description = L"VMware Carbon Black EDR";
	softwareList[7].category = L"EDR";

	softwareList[8].filename = "cbcomms.exe";
	softwareList[8].description = L"CrowdStrike Falcon Insight XDR";
	softwareList[8].category = L"XDR";

	softwareList[9].filename = "ccsvchst.exe";
	softwareList[9].description = L"Symantec Endpoint Protection";
	softwareList[9].category = L"AV";

	softwareList[10].filename = "cpd.exe";
	softwareList[10].description = L"Check Point Daemon";
	softwareList[10].category = L"Security";

	softwareList[11].filename = "cpx.exe";
	softwareList[11].description = L"SentinelOne Singularity XDR";
	softwareList[11].category = L"XDR";

	softwareList[12].filename = "csfalconservice.exe";
	softwareList[12].description = L"CrowdStrike Falcon Insight XDR";
	softwareList[12].category = L"XDR";

	softwareList[13].filename = "cybereason.exe";
	softwareList[13].description = L"Cybereason EDR";
	softwareList[13].category = L"EDR";

	softwareList[14].filename = "cytomicendpoint.exe";
	softwareList[14].description = L"Cytomic Orion";
	softwareList[14].category = L"Security";

	softwareList[15].filename = "dlpagent.exe";
	softwareList[15].description = L"Symantec DLP Agent";
	softwareList[15].category = L"DLP";

	softwareList[16].filename = "dlpsensor.exe";
	softwareList[16].description = L"McAfee DLP Sensor";
	softwareList[16].category = L"DLP";

	softwareList[17].filename = "dsmonitor.exe";
	softwareList[17].description = L"DriveSentry";
	softwareList[17].category = L"Security";

	softwareList[18].filename = "dwengine.exe";
	softwareList[18].description = L"DriveSentry";
	softwareList[18].category = L"Security";

	softwareList[19].filename = "edpa.exe";
	softwareList[19].description = L"McAfee Endpoint Security";
	softwareList[19].category = L"AV";

	softwareList[20].filename = "egui.exe";
	softwareList[20].description = L"ESET NOD32 AV";
	softwareList[20].category = L"AV";

	softwareList[21].filename = "ekrn.exe";
	softwareList[21].description = L"ESET NOD32 AV";
	softwareList[21].category = L"AV";

	softwareList[22].filename = "firesvc.exe";
	softwareList[22].description = L"FireEye Endpoint Agent";
	softwareList[22].category = L"Security";

	softwareList[23].filename = "firetray.exe";
	softwareList[23].description = L"FireEye Endpoint Agent";
	softwareList[23].category = L"Security";

	softwareList[24].filename = "fortiedr.exe";
	softwareList[24].description = L"FortiEDR";
	softwareList[24].category = L"EDR";

	softwareList[25].filename = "fw.exe";
	softwareList[25].description = L"Check Point Firewall";
	softwareList[25].category = L"Firewall";

	softwareList[26].filename = "hips.exe";
	softwareList[26].description = L"Host Intrusion Prevention System";
	softwareList[26].category = L"HIPS";

	softwareList[27].filename = "kpf4ss.exe";
	softwareList[27].description = L"Kerio Personal Firewall";
	softwareList[27].category = L"Firewall";

	softwareList[28].filename = "mbamservice.exe";
	softwareList[28].description = L"Malwarebytes";
	softwareList[28].category = L"AV";

	softwareList[29].filename = "mbamtray.exe";
	softwareList[29].description = L"Malwarebytes";
	softwareList[29].category = L"AV";

	softwareList[30].filename = "mcshield.exe";
	softwareList[30].description = L"McAfee VirusScan";
	softwareList[30].category = L"AV";

	softwareList[31].filename = "mfefire.exe";
	softwareList[31].description = L"McAfee Host Intrusion Prevention";
	softwareList[31].category = L"HIPS";

	softwareList[32].filename = "msascuil.exe";
	softwareList[32].description = L"Windows Defender";
	softwareList[32].category = L"AV";

	softwareList[33].filename = "msmpeng.exe";
	softwareList[33].description = L"Windows Defender";
	softwareList[33].category = L"AV";

	softwareList[34].filename = "msseces.exe";
	softwareList[34].description = L"Microsoft Security Essentials";
	softwareList[34].category = L"AV";

	softwareList[35].filename = "nissrv.exe";
	softwareList[35].description = L"Microsoft Security Essentials";
	softwareList[35].category = L"AV";

	softwareList[36].filename = "outpost.exe";
	softwareList[36].description = L"Agnitum Outpost Firewall";
	softwareList[36].category = L"Firewall";

	softwareList[37].filename = "panda_url_filtering.exe";
	softwareList[37].description = L"Panda Security";
	softwareList[37].category = L"AV";

	softwareList[38].filename = "pavfnsvr.exe";
	softwareList[38].description = L"Panda Security";
	softwareList[38].category = L"AV";

	softwareList[39].filename = "pavsrv.exe";
	softwareList[39].description = L"Panda Security";
	softwareList[39].category = L"AV";

	softwareList[40].filename = "psanhost.exe";
	softwareList[40].description = L"Panda Security";
	softwareList[40].category = L"AV";

	softwareList[41].filename = "rtvscan.exe";
	softwareList[41].description = L"Symantec Endpoint Protection";
	softwareList[41].category = L"AV";

	softwareList[42].filename = "savservice.exe";
	softwareList[42].description = L"Sophos Endpoint Security";
	softwareList[42].category = L"AV";

	softwareList[43].filename = "shstat.exe";
	softwareList[43].description = L"McAfee VirusScan";
	softwareList[43].category = L"AV";

	softwareList[44].filename = "sophosav.exe";
	softwareList[44].description = L"Sophos Endpoint Security";
	softwareList[44].category = L"AV";

	softwareList[45].filename = "sophossps.exe";
	softwareList[45].description = L"Sophos Endpoint Security";
	softwareList[45].category = L"AV";

	softwareList[46].filename = "sophosui.exe";
	softwareList[46].description = L"Sophos Endpoint Security";
	softwareList[46].category = L"AV";

	softwareList[47].filename = "sysmon.exe";
	softwareList[47].description = L"Microsoft Sysmon";
	softwareList[47].category = L"Security";

	softwareList[48].filename = "tanclient.exe";
	softwareList[48].description = L"Tanium EDR";
	softwareList[48].category = L"EDR";

	softwareList[49].filename = "tmntsrv.exe";
	softwareList[49].description = L"Trend Micro OfficeScan";
	softwareList[49].category = L"AV";

	softwareList[50].filename = "tmproxy.exe";
	softwareList[50].description = L"Trend Micro OfficeScan";
	softwareList[50].category = L"AV";

	softwareList[51].filename = "trapsagent.exe";
	softwareList[51].description = L"Palo Alto Networks Cortex XDR";
	softwareList[51].category = L"XDR";

	softwareList[52].filename = "trapsd.exe";
	softwareList[52].description = L"Palo Alto Networks Cortex XDR";
	softwareList[52].category = L"XDR";

	softwareList[53].filename = "truecrypt.exe";
	softwareList[53].description = L"TrueCrypt";
	softwareList[53].category = L"Encryption";

	softwareList[54].filename = "vsserv.exe";
	softwareList[54].description = L"Bitdefender Total Security";
	softwareList[54].category = L"AV";

	softwareList[55].filename = "wrsa.exe";
	softwareList[55].description = L"Webroot Anywhere";
	softwareList[55].category = L"AV";

	softwareList[56].filename = "windefend.exe";
	softwareList[56].description = L"Windows Defender";
	softwareList[56].category = L"AV";

	softwareList[57].filename = "xagt.exe";
	softwareList[57].description = L"FireEye HX";
	softwareList[57].category = L"Security";

	softwareList[58].filename = "ahnsd.exe";
	softwareList[58].description = L"AhnLab V3 Internet Security";
	softwareList[58].category = L"AV";

	softwareList[59].filename = "amsiagent.exe";
	softwareList[59].description = L"Bromium AMSI Agent";
	softwareList[59].category = L"Security";

	softwareList[60].filename = "avkwctl.exe";
	softwareList[60].description = L"K7 Total Security";
	softwareList[60].category = L"AV";

	softwareList[61].filename = "avmailc.exe";
	softwareList[61].description = L"Avira MailGuard";
	softwareList[61].category = L"AV";

	softwareList[62].filename = "avgemc.exe";
	softwareList[62].description = L"AVG Email Scanner";
	softwareList[62].category = L"AV";

	softwareList[63].filename = "avgidsagent.exe";
	softwareList[63].description = L"AVG Identity Protection";
	softwareList[63].category = L"Security";

	softwareList[64].filename = "avkmgr.exe";
	softwareList[64].description = L"K7 Total Security";
	softwareList[64].category = L"AV";

	softwareList[65].filename = "avshadow.exe";
	softwareList[65].description = L"Avira Shadow Copy Service";
	softwareList[65].category = L"AV";

	softwareList[66].filename = "avwebgrd.exe";
	softwareList[66].description = L"Avira Web Protection";
	softwareList[66].category = L"AV";

	softwareList[67].filename = "bavtray.exe";
	softwareList[67].description = L"Baidu Antivirus";
	softwareList[67].category = L"AV";

	softwareList[68].filename = "bavupdat.exe";
	softwareList[68].description = L"Baidu Antivirus Updater";
	softwareList[68].category = L"AV";

	softwareList[69].filename = "bdredline.exe";
	softwareList[69].description = L"Bitdefender Redline";
	softwareList[69].category = L"AV";

	softwareList[70].filename = "bdsubwiz.exe";
	softwareList[70].description = L"Bitdefender Submission Wizard";
	softwareList[70].category = L"AV";

	softwareList[71].filename = "cfp.exe";
	softwareList[71].description = L"COMODO Firewall";
	softwareList[71].category = L"Firewall";

	softwareList[72].filename = "cmdagent.exe";
	softwareList[72].description = L"COMODO Internet Security";
	softwareList[72].category = L"AV";

	softwareList[73].filename = "csavtray.exe";
	softwareList[73].description = L"Centennial Endpoint Security";
	softwareList[73].category = L"AV";

	softwareList[74].filename = "csinsm32.exe";
	softwareList[74].description = L"Centennial Endpoint Security";
	softwareList[74].category = L"AV";

	softwareList[75].filename = "fprot.exe";
	softwareList[75].description = L"F-Prot Antivirus";
	softwareList[75].category = L"AV";

	softwareList[76].filename = "fpwin.exe";
	softwareList[76].description = L"F-Prot Antivirus";
	softwareList[76].category = L"AV";

	softwareList[77].filename = "frzstate2k.exe";
	softwareList[77].description = L"Faronics Deep Freeze";
	softwareList[77].category = L"Security";

	softwareList[78].filename = "gdatpagent.exe";
	softwareList[78].description = L"Symantec Data Loss Prevention";
	softwareList[78].category = L"DLP";

	softwareList[79].filename = "gfiarksvc.exe";
	softwareList[79].description = L"GFI LanGuard";
	softwareList[79].category = L"Security";

	softwareList[80].filename = "gfiarktray.exe";
	softwareList[80].description = L"GFI LanGuard";
	softwareList[80].category = L"Security";

	softwareList[81].filename = "hexisagent.exe";
	softwareList[81].description = L"Hexis HawkEye G";
	softwareList[81].category = L"EDR";

	softwareList[82].filename = "hexiscybereye.exe";
	softwareList[82].description = L"Hexis CyberEye";
	softwareList[82].category = L"Security";

	softwareList[83].filename = "k7avtray.exe";
	softwareList[83].description = L"K7 Total Security";
	softwareList[83].category = L"AV";

	softwareList[84].filename = "k7rtscan.exe";
	softwareList[84].description = L"K7 Total Security";
	softwareList[84].category = L"AV";

	softwareList[85].filename = "k7uascan.exe";
	softwareList[85].description = L"K7 Total Security";
	softwareList[85].category = L"AV";

	softwareList[86].filename = "k7upschdl.exe";
	softwareList[86].description = L"K7 Total Security";
	softwareList[86].category = L"AV";

	softwareList[87].filename = "k7wscsvc.exe";
	softwareList[87].description = L"K7 Total Security";
	softwareList[87].category = L"AV";

	softwareList[88].filename = "k7wscwiz.exe";
	softwareList[88].description = L"K7 Total Security";
	softwareList[88].category = L"AV";

	softwareList[89].filename = "languard.exe";
	softwareList[89].description = L"GFI LanGuard";
	softwareList[89].category = L"Security";

	softwareList[90].filename = "mbae.exe";
	softwareList[90].description = L"Malwarebytes Anti-Exploit";
	softwareList[90].category = L"Security";

	softwareList[91].filename = "nxclient.exe";
	softwareList[91].description = L"Nexusguard Endpoint Protection";
	softwareList[91].category = L"AV";

	softwareList[92].filename = "nxtray.exe";
	softwareList[92].description = L"Nexusguard Endpoint Protection";
	softwareList[92].category = L"AV";

	softwareList[93].filename = "panda_tpsrv.exe";
	softwareList[93].description = L"Panda Security";
	softwareList[93].category = L"AV";

	softwareList[94].filename = "pcmaticrt.exe";
	softwareList[94].description = L"PC Matic Real-Time";
	softwareList[94].category = L"AV";

	softwareList[95].filename = "pcmatrtsystray.exe";
	softwareList[95].description = L"PC Matic";
	softwareList[95].category = L"AV";

	softwareList[96].filename = "pclxav.exe";
	softwareList[96].description = L"PC-Linq AntiVirus";
	softwareList[96].category = L"AV";

	softwareList[97].filename = "pcmaticsvc.exe";
	softwareList[97].description = L"PC Matic";
	softwareList[97].category = L"AV";

	softwareList[98].filename = "qhpserver.exe";
	softwareList[98].description = L"Qihoo 360 Total Security";
	softwareList[98].category = L"AV";

	softwareList[99].filename = "qihoo_ts.exe";
	softwareList[99].description = L"Qihoo 360 Total Security";
	softwareList[99].category = L"AV";

	softwareList[100].filename = "sbamsvc.exe";
	softwareList[100].description = L"VIPRE Antivirus";
	softwareList[100].category = L"AV";

	softwareList[101].filename = "sbamtray.exe";
	softwareList[101].description = L"VIPRE Antivirus";
	softwareList[101].category = L"AV";

	softwareList[102].filename = "sbamui.exe";
	softwareList[102].description = L"VIPRE Antivirus";
	softwareList[102].category = L"AV";

	softwareList[103].filename = "sfc.exe";
	softwareList[103].description = L"System File Checker";
	softwareList[103].category = L"Security";

	softwareList[104].filename = "smc.exe";
	softwareList[104].description = L"Symantec Endpoint Protection";
	softwareList[104].category = L"AV";

	softwareList[105].filename = "sophoscleaner.exe";
	softwareList[105].description = L"Sophos Virus Removal Tool";
	softwareList[105].category = L"AV";

	softwareList[106].filename = "sophoshealth.exe";
	softwareList[106].description = L"Sophos Endpoint Security";
	softwareList[106].category = L"AV";

	softwareList[107].filename = "sophosinstaller.exe";
	softwareList[107].description = L"Sophos Endpoint Security";
	softwareList[107].category = L"AV";

	softwareList[108].filename = "sophosmcsagentd.exe";
	softwareList[108].description = L"Sophos Endpoint Security";
	softwareList[108].category = L"AV";

	softwareList[109].filename = "sophosntivirus.exe";
	softwareList[109].description = L"Sophos Endpoint Security";
	softwareList[109].category = L"AV";

	softwareList[110].filename = "swdoctor.exe";
	softwareList[110].description = L"Spyware Doctor";
	softwareList[110].category = L"AV";

	softwareList[111].filename = "swupdate.exe";
	softwareList[111].description = L"Spyware Doctor";
	softwareList[111].category = L"AV";

	softwareList[112].filename = "symcorpui.exe";
	softwareList[112].description = L"Symantec Endpoint Protection";
	softwareList[112].category = L"AV";

	softwareList[113].filename = "symerr.exe";
	softwareList[113].description = L"Symantec Endpoint Protection";
	softwareList[113].category = L"AV";

	softwareList[114].filename = "symlcsvc.exe";
	softwareList[114].description = L"Symantec Endpoint Protection";
	softwareList[114].category = L"AV";

	softwareList[115].filename = "symwsc.exe";
	softwareList[115].description = L"Symantec Endpoint Protection";
	softwareList[115].category = L"AV";

	softwareList[116].filename = "tsmains.exe";
	softwareList[116].description = L"Tencent PC Manager";
	softwareList[116].category = L"AV";

	softwareList[117].filename = "tsvncache.exe";
	softwareList[117].description = L"Tencent PC Manager";
	softwareList[117].category = L"AV";

	softwareList[118].filename = "umbrella.exe";
	softwareList[118].description = L"Cisco Umbrella";
	softwareList[118].category = L"Security";

	softwareList[119].filename = "umbrella_roamingclient.exe";
	softwareList[119].description = L"Cisco Umbrella Roaming Client";
	softwareList[119].category = L"Security";

	softwareList[120].filename = "viprerestart.exe";
	softwareList[120].description = L"VIPRE Antivirus";
	softwareList[120].category = L"AV";

	softwareList[121].filename = "vpc.exe";
	softwareList[121].description = L"Virus Protection Center";
	softwareList[121].category = L"AV";

	softwareList[122].filename = "webinspect.exe";
	softwareList[122].description = L"HP WebInspect";
	softwareList[122].category = L"Security";

	softwareList[123].filename = "webrootsecureanywhere.exe";
	softwareList[123].description = L"Webroot SecureAnywhere";
	softwareList[123].category = L"AV";

	softwareList[124].filename = "wpctrl.exe";
	softwareList[124].description = L"Webroot Parental Controls";
	softwareList[124].category = L"Security";

	softwareList[125].filename = "wpff.exe";
	softwareList[125].description = L"Webroot Parental Controls";
	softwareList[125].category = L"Security";

	softwareList[126].filename = "wscsvc.exe";
	softwareList[126].description = L"Windows Security Center";
	softwareList[126].category = L"Security";

	softwareList[127].filename = "zanda.exe";
	softwareList[127].description = L"ZoneAlarm Antivirus";
	softwareList[127].category = L"AV";

	softwareList[128].filename = "zatutor.exe";
	softwareList[128].description = L"ZoneAlarm Antivirus";
	softwareList[128].category = L"AV";

	softwareList[129].filename = "zlclient.exe";
	softwareList[129].description = L"ZoneAlarm Security Suite";
	softwareList[129].category = L"AV";
	//End security product list

	
	//get handle to specified host
	handleHost = WTSAPI32$WTSOpenServerA(hostName);

	//get list of running processes 
	if (!WTSAPI32$WTSEnumerateProcessesA(handleHost, 0, 1, &proc_info, &pi_count)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get a valid handle to the specified host.\n");
		return -1;
	}
	
	if(pi_count == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Couldn't list remote processes. Do you have enough privileges on the remote host?\n");
		return -1;
	}

	//compare list with running processes
	internal_printf("Description\t\t\t\t\tCategory\n==============================================================\n");
	for (int i = 0 ; i < pi_count ; i++ ) {
		procName = proc_info[i].pProcessName;
		
		for (size_t i = 0; procName[i]; i++) {
            procName[i] = MSVCRT$tolower(procName[i]); 
        }
		
		for (size_t i = 0; i < numSoftware; i++) {
			if (MSVCRT$strcmp(procName, softwareList[i].filename) == 0) {
				internal_printf("%-50ls\t%ls\n", softwareList[i].description, softwareList[i].category);
				foundSecProduct = true;
                break;
            }
		}
		procName = NULL;
	}
	
	if (foundSecProduct) {
        printoutput(TRUE);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "No running security processes were found.\n");
    }
	
	WTSAPI32$WTSCloseServer(handleHost);
	KERNEL32$VirtualFree(softwareList, 0, MEM_RELEASE);

    return 0;
}



