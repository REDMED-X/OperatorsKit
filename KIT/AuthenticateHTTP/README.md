# AuthenticateHTTP
This tool can be used to force a Windows-authenticated HTTP request from the current user context to a (ntlmrelayx) server for an authenticated (LDAP) relay attack. 

>With WinINet, automatic logon is controlled by security zone settings. To enable auto-logon, you must specify either `localhost` or the target system's NetBIOS name so it is recognized as part of the Local Intranet zone. Furthermore, this tool must be run in a second beacon that is not running the SOCKS and rportfwd.  

## Arguments
* `host`: hostname or locahost to send the Windows authentication to
* `port`: port number to send the Windows autentication to

## Usage
* `authenticatehttp <host> <port>`

## Examples
* `authenticatehttp localhost 8080`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
