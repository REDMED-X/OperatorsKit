# EnumSecProducts
Get a list of security products like AV/EDR that are running on the current- or remote host. This is done by comparing running processes against a hardcoded list of 130 security products.

## Arguments
* `[hostname]`: The hostname/FQDN/IP of the remote host OR leave empty for the current system.\n\n" .

## Usage
* `enumsecproducts <(optional) hostname>`

## Examples
* `enumsecproducts`
* `enumsecproducts WS01.example.local`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


