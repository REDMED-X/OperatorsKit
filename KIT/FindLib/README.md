# FindLib
Find a specific loaded module in all processes or list all loaded modules in a specific process.

## Options
* `search`: find all processes that have loaded a specific module (e.g. winhttp.dll or ws2_32.dll).
* `list`: list all loaded modules in a remote process.

## Usage
* `findlib search <module name>`
* `findlib list <pid>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
