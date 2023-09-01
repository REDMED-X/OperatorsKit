# PSremote
Get a list of all processes running on the remote host.

## Options
* `<FQDN or IP>`: specify the target host FQDN or IP. 

## Usage
* `psremote <FQDN or IP remote host>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
