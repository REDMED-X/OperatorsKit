# PasswordSprayLocal
Validate a single local username and password against a list of target hostnames using SMB authentication (IPC$).

>A valid list with usernames is considered newline separated. 

## Arguments
* `path to hostnames file`: attacker-side path to hostname list (newline separated).
* `username`: local account username.
* `password`: password to validate.
* `sleeptimer`: (optional) seconds between attempts (default 5).
* `jitter`: (optional) jitter percentage (default 20).

	
## Usage
* `passwordspraylocal <path to hostnames file> <username> <password> [opt <sleeptimer>] [opt <jitter>]`


## Examples
* `passwordspraylocal C:/Users/RTO/Documents/computers.txt localadmin Welcome01 10 40`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
