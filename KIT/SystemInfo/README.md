# SystemInfo
Enumerate system information via WMI. 

>This tool has some serious limitations due the fact that COM security settings only can be set once. So if the current process already used COM -and most likely called CoInitializeSecurity API- the security setting can't be set for a second time. This results in the situation that most of the time security permissions don't allow for this tool to run if the beacon is started in an existing process. 

If you know a solution for the double CoInitializeSecurity call problem (RPC_E_TOO_LATE) or how to fetch the data without getting the WBEM_E_ACCESS_DENIED error, please let me know!


## Usage
* `systeminfo`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
