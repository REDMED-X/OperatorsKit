# OperatorsKit
This repository features a collection of tools designed to integrate with Cobalt Strike (and other C2 frameworks) via Beacon Object Files (BOFs). 

Maintained by **Western Tactics**, these tools are open-sourced to help Red Teams build stronger defenses against evolving cyber threats.

🌐 **Want to learn more? Discover our practical cyber security courses:** [westerntactics.com](https://westerntactics.com)


## Kit content
The following tools are currently in the OperatorsKit: 

|Name|Description|
|----|----------|
|**[AddExclusion](KIT/AddExclusion)**|Add a new exclusion to Windows Defender for a folder, file, process or extension.|
|**[AddFirewallRule](KIT/AddFirewallRule)**|Add a new inbound/outbound firewall rule.|
|**[AddLocalCert](KIT/AddLocalCert)**|Add a (self signed) certificate to a specific local computer certificate store.|
|**[AddTaskScheduler](KIT/AddTaskScheduler)**|Create a scheduled task on the current- or remote host.|
|**[AuthenticateHTTP](KIT/AuthenticateHTTP)**|Force a Windows-authenticated HTTP request from the current user context.|
|**[CaptureNetNTLM](KIT/CaptureNetNTLM)**|Capture the NetNTLMv2 hash of the current user.|
|**[CredPrompt](KIT/CredPrompt)**|Start persistent credential prompt in an attempt to capture user credentials.|
|**[DcomLocalServer32](KIT/DcomLocalServer32)**|Instantiate a DCOM/COM class and start an EXE on a (remote) machine.|
|**[DelExclusion](KIT/DelExclusion)**|Delete an exclusion from Windows Defender for a folder, file, process or extension.|
|**[DelFirewallRule](KIT/DelFirewallRule)**|Delete a firewall rule.|
|**[DelLocalCert](KIT/DelLocalCert)**|Delete a local computer certificate from a specific store.|
|**[DelTaskScheduler](KIT/DelTaskScheduler)**|Delete a scheduled task on the current- or a remote host.|
|**[DllEnvHijacking](KIT/DllEnvHijacking)**|BOF implementation of DLL environment hijacking.|
|**[EnumActiveHosts](KIT/EnumActiveHosts)**|Enumerate active hosts or validate a single open port.|
|**[EnumDllSideloading](KIT/EnumDllSideloading)**|Enumerate .EXE's for DLL sideloading vulnerabilities.|
|**[EnumDrives](KIT/EnumDrives)**|Enumerate drive letters and type.|
|**[EnumExclusions](KIT/EnumExclusions)**|Check the AV for excluded files, folders, extentions and processes.|
|**[EnumFiles](KIT/EnumFiles)**|Search for matching files based on a word, extention or keyword in the file content.|
|**[EnumHandles](KIT/EnumHandles)**|Enumerate "process" and "thread" handle types between processes.|
|**[EnumLib](KIT/EnumLib)**|Enumerate loaded module(s) in remote process(es).|
|**[EnumLocalCert](KIT/EnumLocalCert)**|Enumerate all local computer certificates from a specific store.|
|**[EnumSecProducts](KIT/EnumSecProducts)**|Enumerate security products (like AV/EDR) that are running on the current/remote host.|
|**[EnumShares](KIT/EnumShares)**|Enumerate remote shares and access level using a predefined list with hostnames.|
|**[EnumSysmon](KIT/EnumSysmon)**|Verify if Sysmon is running by checking the registry and listing Minifilter drivers.|
|**[EnumTaskScheduler](KIT/EnumTaskScheduler)**|Enumerate all scheduled tasks in the root folder.|
|**[EnumWebClient](KIT/EnumWebClient)**|Find hosts with the WebClient service running based on a list with predefined hostnames.|
|**[ExecuteCrossSession](KIT/ExecuteCrossSession)**|Execute a binary in the context of another user via COM cross-session interaction|
|**[ForceLockScreen](KIT/ForceLockScreen)**|Force the lock screen of the current user session.|
|**[HideFile](KIT/HideFile)**|Hide a file or directory by setting it's attributes to systemfile + hidden.|
|**[IdleTime](KIT/IdleTime)**|Check current user activity based on the user's last input.|
|**[InjectPoolParty](KIT/InjectPoolParty)**|Inject beacon shellcode and execute it via Windows Thread Pools.|
|**[KeyloggerRawInput](KIT/KeyloggerRawInput)**|Keylogger based on RegisterRawInputDevices.|
|**[PasswordSprayAD](KIT/PasswordSprayAD)**|Validate a single password against multiple accounts using LDAP/LDAPS/GC/GCS authentication.|
|**[PasswordSprayLocal](KIT/PasswordSprayLocal)**|Validate a single set of credentials against multiple local hosts via SMB.|
|**[PSremote](KIT/PSremote)**|Enumerate all running processes on a remote host.|
|**[SPN](KIT/SPN)**|Targeted kerberoasting with separate enumeration and roasting flows.|
|**[WiFiPasswords](KIT/WiFiPasswords)**|Enumerates all saved SSID's, then retrieves each AP’s stored plaintext password.|

## Usage
Each individual tool has its own README file with usage information and compile instructions. 

You can also directly import the entire suite of tools by loading the `OperatorsKit.cna` script via the Cobalt Strike script manager. Furthermore, mass compilation can be executed by running the `compile_all.bat` script from within an `x64 Native Tools Command Prompt for VS 2019` or `VS 2022` terminal.


## Credits
A round of virtual applause to everyone who laid the groundwork for the development of several of these techniques. Additional credits can be found in each corresponding README file.


## Legal use
This repository is for authorized security testing and education only. Provided "as is"—the authors accept no liability for misuse.
