# SilenceSysmon
Silence the Sysmon service by patching its capability to write ETW events to the log.

Restarting the Sysmon service or the system itself will clear the patch and Sysmon will resume working normally. Altough this will not leave any traces in the log, there will be a time gap between the last and first new event.

## Options
* `<pid>`: the process ID of the Sysmon service running on the system.

## Usage
* `silencesysmon <sysmon pid>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
