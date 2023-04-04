# DelTaskScheduler
Delete a scheduled task on the current system or a remote host.

>The tool returns error codes if the operation fails. The most common error codes for deleting a task are: 80070005 (not enough privileges), and 80070002 (scheduled task doesn't exist). 

## Arguments
* `taskName`: The name of the scheduled task.
* `hostName`: The FQDN of the remote host or leave empty for the current system. 

## Usage
* `deltaskscheduler <taskName> <(optional) hostName>`

## Examples
* `deltaskscheduler TestTask`
* `deltaskscheduler TestTask DB01.example.local`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

