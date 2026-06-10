# EnumDllSideloading
Enumerate a single .EXE, a folder or all folders recursively to identify DLL sideloading vulnerabilities in executables. 

>This tool can be used both locally and remotely. For remote usage, specify an UNC path instead of a local path.

## Arguments
* `<path>`: Specify the path to the single .EXE or the folder that you want to check for DLL sideloading vulnerabilities.
* `<mode>`: Select one of the following enumeration modes: `single` (target single .EXE, best for OPSEC), `folder` (all the .EXE's in the specified folder), `recursive` (all .EXE's in the specified- and sub folders).

## Usage
* `enumdllsideloading <path> <mode>`

## Examples
* `enumdllsideloading C:\Users\John\Documents\Autoruns64.exe single`
* `enumdllsideloading C:\Users\John\Documents\ folder`
* `enumdllsideloading \\examplehost\C$\Users\John\Documents\ recursive`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


