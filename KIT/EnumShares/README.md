# EnumShares
List remote shares and there access level using a list with predefined hostnames or IP addresses. The list is loaded from your own attacker system.

>A valid list with hostnames is considered newline separated and ends with a newline. Furthermore, the following hostname notations are correct: `database`, `database.example.local`, `10.100.10.1`.  

## Arguments
* `<path to file>`: the path on your own attacker system to the file containing the list with predefined hostnames.


## Usage
* `enumshares <path to hostname file> `


## Examples
* `enumshares C:\Users\RTO\Documents\hostnames.txt`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
