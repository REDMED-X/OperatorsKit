# EnumLocalCert
List all local computer certificates from a specific store. Common store names are: ROOT, MY, TRUST, CA, USERDS, AuthRoot, Disallowed.

## Arguments
* `<store name>`: the name of the certificate store.

## Usage
* `enumlocalcert <store name>`

## Example
* `enumlocalcert ROOT`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
