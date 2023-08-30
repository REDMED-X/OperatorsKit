# EnumTaskScheduler
Enumerate and list all the scheduled tasks in the root folder. 

>This will only return basic information about the scheduled task in the root folder. For a more comprehensive output and a complete list of all the scheduled tasks on the host, use the schtasksenum BOF from [TrustedSec](https://github.com/trustedsec/CS-Situational-Awareness-BOF).

## Parameters
* `hostName`: Specify `""` for the current system or the FQDN of the remote host: `DB01.example.local`. 


## Usage
* `enumtaskscheduler <(optional) hostName>`


## Examples
* `enumtaskscheduler`
* `enumtaskscheduler DB01.example.local`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
