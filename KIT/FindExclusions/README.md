# FindExclusions
Check Windows Defender for excluded files, folders, extentions and processes.

>This operation requires elevated privileges. Furthermore, currently only Windows Defender exclusions are supported. However, this code is easily enhanced to also support other AV products that communicate via WMI. 


## Usage
* `findexclusions`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
