# OperatorsKit
This repository contains a collection of Beacon Object Files (BOFs) that integrate with Cobalt Strike.  

## Kit content
The following tools are currently in the OperatorsKit: 

|Name|Description|
|----|----------|
|**[AddExclusion](KIT/AddExclusion)**|Add a new exclusion to Windows Defender for a folder, file, process or extension.|
|**[AddFirewallRule](KIT/AddFirewallRule)**|Add a new inbound/outbound firewall rule.|
|**[AddLocalCert](KIT/AddLocalCert)**|Add a (self signed) certificate to a specific local computer certificate store.|
|**[AddTaskScheduler](KIT/AddTaskScheduler)**|Create a scheduled task on the current- or remote host.|
|**[BlindEventlog](KIT/BlindEventlog)**|Blind Eventlog by suspending its threads.|
|**[CaptureNetNTLM](KIT/CaptureNetNTLM)**|Capture the NetNTLMv2 hash of the current user.|
|**[CredPrompt](KIT/CredPrompt)**|Start persistent credential prompt in an attempt to capture user credentials.|
|**[DelExclusion](KIT/DelExclusion)**|Delete an exclusion from Windows Defender for a folder, file, process or extension.|
|**[DelFirewallRule](KIT/DelFirewallRule)**|Delete a firewall rule.|
|**[DelLocalCert](KIT/DelLocalCert)**|Delete a local computer certificate from a specific store.|
|**[DelTaskScheduler](KIT/DelTaskScheduler)**|Delete a scheduled task on the current- or a remote host.|
|**[DllComHijacking](KIT/DllComHijacking)**|Leverage DLL Hijacking by instantiating a COM object on a target host |
|**[DllEnvHijacking](KIT/DllEnvHijacking)**|BOF implementation of DLL environment hijacking published by [Wietze](https://www.wietzebeukema.nl/blog/save-the-environment-variables).|
|**[EnumDotnet](KIT/EnumDotnet)**|Enumerate processes that most likely have .NET loaded.|
|**[EnumDrives](KIT/EnumDrives)**|Enumerate drive letters and type.|
|**[EnumExclusions](KIT/EnumExclusions)**|Check the AV for excluded files, folders, extentions and processes.|
|**[EnumFiles](KIT/EnumFiles)**|Search for matching files based on a word, extention or keyword in the file content.|
|**[EnumHandles](KIT/EnumHandles)**|Enumerate "process" and "thread" handle types between processes.|
|**[EnumLib](KIT/EnumLib)**|Enumerate loaded module(s) in remote process(es).|
|**[EnumLocalCert](KIT/EnumLocalCert)**|Enumerate all local computer certificates from a specific store.|
|**[EnumRWX](KIT/EnumRWX)**|Enumerate RWX memory regions in a target process.|
|**[EnumSecProducts](KIT/EnumSecProducts)**|Enumerate security products (like AV/EDR) that are running on the current/remote host.|
|**[EnumShares](KIT/EnumShares)**|Enumerate remote shares and your access level using a predefined list with hostnames.|
|**[EnumSysmon](KIT/EnumSysmon)**|Verify if Sysmon is running by checking the registry and listing Minifilter drivers.|
|**[EnumTaskScheduler](KIT/EnumTaskScheduler)**|Enumerate all scheduled tasks in the root folder.|
|**[EnumWebClient](KIT/EnumWebClient)**|Find hosts with the WebClient service running based on a list with predefined hostnames.|
|**[EnumWSC](KIT/EnumWSC)**|List what security products are registered in Windows Security Center.|
|**[ForceLockScreen](KIT/ForceLockScreen)**|Force the lock screen of the current user session.|
|**[HideFile](KIT/HideFile)**|Hide a file or directory by setting it's attributes to systemfile + hidden.|
|**[IdleTime](KIT/IdleTime)**|Check current user activity based on the user's last input.|
|**[InjectPoolParty](KIT/InjectPoolParty)**|Inject beacon shellcode and execute it via [Windows Thread Pools](https://github.com/SafeBreach-Labs/PoolParty/)|
|**[LoadLib](KIT/LoadLib)**|Load an on disk present DLL via RtlRemoteCall API in a remote process.|
|**[PSremote](KIT/PSremote)**|Enumerate all running processes on a remote host.|
|**[PasswordSpray](KIT/PasswordSpray)**|Validate a single password against multiple accounts using kerberos authentication.|
|**[SilenceSysmon](KIT/SilenceSysmon)**|Silence the Sysmon service by patching its capability to write ETW events to the log.|
|**[SystemInfo](KIT/SystemInfo)**|Enumerate system information via WMI (limited use case).|

## Usage
Each individual tool has its own README file with usage information and compile instructions. 

It is also possible to directly import all tools by loading the `OperatorsKit.cna` script using the Cobalt Strike script manager. Furthermore, mass compiling can now be done using the `compile_all.bat` script from within the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal. 

## Credits
A round of virtual applause to [reenz0h](https://twitter.com/SEKTOR7net). Multiple tools in this kit are based on his code examples from the Malware Development and Windows Evasion courses. I highly recommend purchasing them!

Furthermore, some code from the [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/base.c) project is used to neatly print beacon output. 
