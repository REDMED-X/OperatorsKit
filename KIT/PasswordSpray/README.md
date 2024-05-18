# PasswordSpray
Validate a single password against multiple accounts using kerberos authentication and a list with predefined usernames. The list can be loaded from your own attacker system.

>A valid list with usernames is considered newline separated. 

## Arguments
* `<path to username file>`: the path on your own attacker system to a file containing the list with usernames. Each username must be newline separated.
* `<password>`: the password to validate against the usernames.
* `<domain>`: FQDN of the domain.
* `<sleeptimer>`: (optional) sleep timer in seconds to wait between each authentication attempt (default is 0).
* `<jitter>`: (optional) jitter in percentage (default 0).
	
## Usage
* `passwordspray <path to username file> <password> <domain> [opt <sleeptimer>] [opt <jitter>]`


## Examples
* `passwordspray C:\Users\redmed\Documents\usernames.txt Welcome01 example.local 10 40`
* `passwordspray C:\Users\redmed\Documents\usernames.txt Welcome01 example.local`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
