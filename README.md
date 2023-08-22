# OperatorsKit
This repository contains a collection of tools that integrate with Cobalt Strike through Beacon Object Files (BOFs).  

## Kit content
The following tools are currently in the operators' kit: 

|Name|Decription|
|----|----------|
|**[AddLocalCert](KIT/AddLocalCert)**|Add a (self signed) certificate to a specific local computer certificate store.|
|**[AddTaskScheduler](KIT/AddTaskScheduler)**|Create a scheduled task on the current- or remote host.|
|**[BlindEventlog](KIT/BlindEventlog)**|Blind Eventlog by suspending its threads.|
|**[CaptureNetNTLM](KIT/CaptureNetNTLM)**|Capture the NetNTLMv2 hash of the current user.|
|**[CredPrompt](KIT/CredPrompt)**|Start persistent credential prompt in an attempt to capture user credentials.|
|**[DelLocalCert](KIT/DelLocalCert)**|Delete a local computer certificate from a specific store.|
|**[DelTaskScheduler](KIT/DelTaskScheduler)**|Delete a scheduled task on the current- or a remote host.|
|**[DllEnvHijacking](KIT/DllEnvHijacking)**|BOF implementation of DLL environment hijacking published by [Wietze](https://www.wietzebeukema.nl/blog/save-the-environment-variables).|
|**[EnumLocalCert](KIT/EnumLocalCert)**|List all local computer certificates from a specific store.|
|**[EnumSecProducts](KIT/EnumSecProducts)**|List security products (like AV/EDR) that are running on the system.|
|**[EnumTaskScheduler](KIT/EnumTaskScheduler)**|Enumerate and list all the scheduled tasks in the root folder.|
|**[FindDotnet](KIT/FindDotnet)**|Find processes that most likely have .NET loaded.|
|**[FindHandle](KIT/FindHandle)**|Find "process" and "thread" handle types between processes.|
|**[FindLib](KIT/FindLib)**|Find loaded module(s) in remote process(es).|
|**[FindRWX](KIT/FindRWX)**|Find RWX memory regions in a target process.|
|**[FindSysmon](KIT/FindSysmon)**|Verify if Sysmon is running through enumerating Minifilter drivers and checking the registry.|
|**[FindWebClient](KIT/FindWebClient)**|Find hosts with the WebClient service running based on a list with predefined hostnames.|
|**[ForceLockScreen](KIT/ForceLockScreen)**|Force the lock screen of the current user session.|
|**[HideFile](KIT/HideFile)**|Hide file or directory by setting it's attributes to systemfile + hidden.|
|**[IdleTime](KIT/IdleTime)**|Check current user activity based on the user's last input.|
|**[LoadLib](KIT/LoadLib)**|Load an on disk present DLL via RtlRemoteCall API in a remote process.|
|**[PSremote](KIT/PSremote)**|List all running processes on a remote host.|
|**[SilenceSysmon](KIT/SilenceSysmon)**|Silence the Sysmon service by patching its capability to write ETW events to the log.|

## Usage
Each individual tool has its own README file with usage information and compile instructions. 

## Credits
A round of virtual applause to [reenz0h](https://twitter.com/SEKTOR7net). Lots of tools in this kit are based on his code examples from the Malware Development and Windows Evasion courses. I highly recommend purchasing them!

Furthermore, some code from the [C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) project is copied to neatly print beacon output. 
