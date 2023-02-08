# DllEnvHijacking
This tool will: setup a hidden file structure, move an already on disk present malicious proxy DLL to the new system32 folder, hide the proxy DLL, modify the SYSTEMROOT environment variable, run the vulnerable binary as a spoofed process to execute the malicious DLL, and reset the original SYSTEMROOT environment variable so the beacon keeps working as intended. 

>Make sure that before you run this tool, you uploaded the malicious proxy DLL to an accessible folder on disk. 

More information about the DLL Environment Hijacking attack can be found [here](https://www.wietzebeukema.nl/blog/save-the-environment-variables). 

## Options
* `<new sysroot dir>:` the new directory name as a path that will be used as the new SYSTEMROOT variable like `C:\Data\` (make sure the directory path ends with `\`)
* `<malicious DLL name>`: the name of the malicious DLL that will be loaded by the vulnerable binary (e.g. mswsock.dll).
* `<path to mal. DLL folder>`: the path on the target system to the folder were the malicious DLL is stored (don't add the DLL name and end the path with a `\`)
* `<name of vulnerable binary>`: the name of the vulnerable binary that will be executed and loads the malicious DLL (e.g. hostname.exe).
* `<pid parent proc>`: the process ID of the parent process under which the vulnerable binary will run as a child (parent process spoofing).

## Usage
* `dllenvhijacking <new sysroot dir> <malicious DLL name> <path to mal. DLL folder> <name of vulnerable binary> <pid parent proc>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
