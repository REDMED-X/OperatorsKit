# AddLocalCert
Add a (self signed) certificate to a specific local computer certificate store. For example, add a self signed certificate -that you also used to sign your malicious binary with- to the \"Trusted Root Certification Authorities\" (ROOT) folder on the local computer. 

>All the properties are filled in based on the metadata in the certificate except the \"Friendly Name\" property. This property needs to be set manually as an argument.


## Arguments
* `<path to certificate file>`: the path on your own attacker system to the `certificate.cer` file.
* `<store name>`: the certificate store name (like `ROOT`) to import the certificate into.
* `<friendly name>`: the name that is set in the `Friendly Name` property


## Usage
* `addlocalcert <path to certificate.cer file> <store name> \"<friendly name>\" `


## Example
* `addlocalcert C:\Users\operator\Documents\examplecert.cer ROOT "Microsoft Root Certificate Authority 2010"`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


