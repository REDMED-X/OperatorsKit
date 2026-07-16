# EnumActiveHosts
Enumerate active hosts or verify a single open port. Tool accepts list with predefined hostnames or IP addresses and is loaded from your own operator client. 

>A valid list with hostnames is considered newline separated and ends with a newline. Furthermore, the following hostname notations are correct: `database`, `database.example.local`, `10.100.10.1`.  

## Arguments
* `<path to file>`: the path on your own attacker system to the file containing the list with predefined hostnames.
* `<port>`: port to validate or use to check if target host is active.
* `<timeout>`: timeout in milliseconds - how long to wait before moving to the next host (default 300 ms).

## Usage
* `enumactivehosts <path to hostname file> <port> <timeout in ms>`

## Examples
* `enumactivehosts C:\Users\RTO\Documents\hostnames.txt 445 100`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
