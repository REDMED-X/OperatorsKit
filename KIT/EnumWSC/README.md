# EnumWSC
Get a list of security products (antivirus, firewall, antispyware) that are registered in the Windows Security Center. 

>This only works if WSC is running (typically only on Windows clients).

## Arguments
* `<option>`: specify one of the following options to request related security information from WSC: `av` (antivirus), `fw` (firewall), `as` (antispyware).`

## Usage
* `enumwsc <option>`

## Examples
* `enumwsc av`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
