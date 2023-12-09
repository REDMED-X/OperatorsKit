# DllComHijacking
This tool is capable of instantiating a COM object based on a provided CLSID on a designated host, which initiates the corresponding process. By focusing on processes susceptible to DLL hijacking and utilizing a gained position that allows writing to the directories from which these processes load their modules, (remote) code execution can be achieved. Consequently, this technique can be effectively employed for lateral movement. 

>Note that before running this tool, the proxy DLL must be manually placed in the correct directory. Additionally, it's important to note that most initiated processes are active for only a brief duration. Therefore, ensure that the proxy DLL performs an action appropriate for such short-lived scenarios.

Below are a couple examples (in some casus, there are multiple missing DLL's):
| CLSID | Process | DLL hijacking option | 
| --- | --- | --- | 
| {94E03510-31B9-47a0-A44E-E932AC86BB17} | wmlaunch.exe | C:\Program Files\Windows Media Player\MPR.dll |
| {494C063B-1024-4DD1-89D3-713784E82044} | PrintBrmEngine.exe | C:\Windows\System32\spool\tools\VERSION.dll |
| {73FDDC80-AEA9-101A-98A7-00AA00374959} | wordpad.exe | C:\Program Files\Windows NT\Accessories\MFC42u.dll |
| {1E2D67D6-F596-4640-84F6-CE09D630E983} | ShapeCollector.exe | C:\Program Files\Common Files\microsoft shared\ink\DUI70.dll |


## Arguments
* `[<CLSID>]` The CLSID of the COM class that is associated with the vulnerable process.
* `[<target>]` The FQDN, hostname or IP of the designated host (can be remote- or the local host).


## Usage
* `dllcomhijacking <CLSID> <target>`


## Example
* `dllcomhijacking {73FDDC80-AEA9-101A-98A7-00AA00374959} target.example.local`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


## Acknowledgements
This tool is based on the [dcomhijack](https://github.com/WKL-Sec/dcomhijack) project from WKL-Sec.