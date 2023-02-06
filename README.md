# OperatorsKit
This repository contains a collection of tools that integrate with Cobalt Strike through Beacon Object Files (BOFs). 

## Kit content
The following tools are currently in the operators' kit: 

|Name|Decription|
|----|----------|
|**[BlindEventlog](KIT/BlindEventlog)**|Blind Eventlog by suspending its threads.|
|**[FindDotnet](KIT/FindDotnet)**|Find processes that most likely have .NET loaded.|
|**[FindHandle](KIT/FindHandle)**|Find "process" and "thread" handle types between processes.|
|**[FindLib](KIT/FindLib)**|Find loaded module(s) in remote process(es).|
|**[FindRWX](KIT/FindRWX)**|Find RWX memory regions in a target process.|
|**[FindSysmon](KIT/FindSysmon)**|Verify if Sysmon is running through enumerating Minifilter drivers and checking the registry.|
|**[LoadLib](KIT/LoadLib)**|Load a on disk present DLL via RtlRemoteCall API in a remote process.|
|**[PSremote](KIT/PSremote)**|List all running processes on a remote host.|
|**[SilenceSysmon](KIT/SilenceSysmon)**|Silence the Sysmon service by patching its capability to write ETW events to the log.|

## Usage
Each individual tool has its own README file with usage information and compile instructions. 

## Credits
A round of virtual applause to [reenz0h](https://twitter.com/SEKTOR7net). Lots of tools in this kit are based on his code examples from the Malware Development and Windows Evasion courses. I highly recommend purchasing them!

Furthermore, some code from the [C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) project is copied to neatly print beacon output. 
