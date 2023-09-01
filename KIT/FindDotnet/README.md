# FindDotnet
Find processes that most likely have .NET loaded by searching for the section name: `\BaseNamedObjects\Cor_Private_IPCBlock(_v4)_<ProcessId>`

## Usage
* `finddotnet`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
