# PasswordSprayAD
Validate single password against multiple accounts using LDAP, LDAPS, GC, or GCS simple bind authentication.

>A valid list with usernames is considered newline separated. 

## Arguments
* `protocol`: the protocol to use (ldap, ldaps, gc, or gcs).
* `path to username file`: the path on your own attacker system to a file containing the list with usernames. Each username must be newline separated.
* `password`: the password to validate.
* `domain`: FQDN of the domain.
* `dc`: Hostname or IP of the Domain Controller to target.
* `sleeptimer`: (optional) sleep timer in seconds to wait between each authentication attempt (default is 5).
* `jitter`: (optional) jitter in percentage (default 20).\n\n" .

	
## Usage
* `passwordsprayad <ldap|ldaps|gc|gcs> <path to username file> <password> <domain> <dc> [opt <sleeptimer>] [opt <jitter>]`


## Examples
* `passwordsprayad gc C:/Users/RTO/Documents/usernames.txt Welcome01 example.local dc01.example.local 10 40`
* `passwordsprayad ldaps C:/Users/RTO/Documents/usernames.txt Welcome01 example.local dc01.example.local`
	

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
