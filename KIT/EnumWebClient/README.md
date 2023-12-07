# EnumWebClient
Enumerate hosts that have the WebClient service running using a list with predefined hostnames or IP addresses. The list is loaded from your own attacker system.

>A valid list with hostnames is considered newline separated and ends with a newline. Furthermore, the following hostname notations are correct: `database`, `database.example.local`, `10.100.10.1`.  

## Arguments
* `<path to file>`: the path on your own attacker system to the file containing the list with predefined hostnames.
* `debug`: optional argument to include hostnames in the output that couldn't be reached or on which the WebClient was not running.


## Usage
* `enumwebclient <path to hostname file> [opt:debug]`


## Examples
* `enumwebclient C:\Users\RTO\Documents\hostnames.txt`
* `enumwebclient C:\\Users\RTO\Documents\hostnames.txt debug`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

## Credits
This project is based on the [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus) BOF and created as a more user friendly version.