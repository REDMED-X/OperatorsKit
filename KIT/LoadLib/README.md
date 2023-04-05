# LoadLib
Load an on disk present DLL via RtlRemoteCall API in a remote process. Depending on the process from which you run this tool, it may or may not work.

## Options
* `<pid>`: specify the target process to load the DLL into. 
* `path`: full path to the on disk present DLL. 

## Usage
* `loadlib <pid> <path to dll>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
