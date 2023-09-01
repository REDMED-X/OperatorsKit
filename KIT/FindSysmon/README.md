# FindSysmon
Verify if Sysmon is running. This can be done by checking the registry or by enumerating Minifilter drivers and search for one that is associated with Sysmon.

## Options
* `reg`: search the registry to check if Sysmon is present on the system and return the Sysmon service PID if active.
* `driver`: list all the Minifilter drivers on the system and check manually if a minifilter is present that is associated with Sysmon (requires elevated privileges).

## Usage
* `findsysmon <reg | driver>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
