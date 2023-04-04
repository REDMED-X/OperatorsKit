# DelLocalCert
Delete a local computer certificate from a specified store based on its unique thumbprint.

## Arguments
* `<store name>`: the name of the certificate store from which to delete the certificate.
* `<thumbprint>`: the thumbprint of the certificate that you want to delete in format (all caps): `AABBCCDDEEFF00112233445566778899AABBCCDD`.

## Usage
* `dellocalcert <store name> <thumbprint>`

## Example
* `dellocalcert ROOT AABBCCDDEEFF00112233445566778899AABBCCDD`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

