# EnumShares
List remote shares and their access level based on a list from your attacker system. This tool performs a quick TCP/445 check to skip offline hosts and uses stealthy attribute checks to verify access.

>A valid list with hostnames is considered newline separated. Furthermore, the following hostname notations are correct: `database`, `database.example.local`, `10.100.10.1`.  

## Arguments
* `path`: Path to the host list file on your attacker system.
* `sleep`: Seconds to wait between each host.
* `jitter`: Percentage of jitter to apply to the sleep (0-100).
* `timeout`: (Optional) Port check timeout in milliseconds (default: 300).


## Usage
* `enumshares <path> <sleep> <jitter> <timeout>`


## Examples
* `enumshares C:\Users\RTO\Documents\hostnames.txt 5 20 500`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
