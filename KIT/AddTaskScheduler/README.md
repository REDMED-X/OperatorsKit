# AddTaskScheduler
This tool can be used to create a scheduled task on the current system or a remote host. It supports multiple trigger options. If the tool is running with elevated privileges, it will automatically set the `Run whether user is logged on or not` security option as `NT AUTHORITY\SYSTEM`. 

>As a rule of thumb, setting a scheduled task for any user but yourself, requires elevated privileges. Furthermore, the tool returns error codes if the operation fails. The most common error codes are: 80070005 (not enough privileges), 80041318/80041319 (most likely you made a typo in one of the input fields), and 80070002 (scheduled task doesn't exist). 

## Basic parameters
* `taskName`: The name of the scheduled task.
* `hostName`: Specify `""` for the current system or the FQDN of the remote host: `DB01.example.local`. 
* `programPath`: Path to the program that you want to run like: `C:\Windows\System32\cmd.exe`.
* `programArguments`: Arguments that you want to pass to the program like: `"/c C:\Windows\System32\calc.exe"` or `""` to leave it empty.
* `triggerType`: The trigger that signals the execution like: `onetime`, `daily`, `logon`, `startup`, `lock`, `unlock`. For more information, check the TRIGGER OPTIONS below.

## Supported trigger options
* `onetime`: Create task with trigger "On a schedule: one time".
* `daily`: Create task with trigger "On a schedule: daily."
* `logon`: Create task with trigger "At log on" (requires elevated privileges if set for another user or all users).
* `startup`: Create task with trigger "At startup" (requires elevated privileges).
* `lock`: Create task with trigger "On workstation lock" (requires elevated privileges if set for another user or all users).
* `unlock`: Create task with trigger "On workstation unlock" (requires elevated privileges if set for another user or all users).

## Trigger specific parameters
* `startTime`: Start time of the trigger in format: `2023-03-24T12:08:00`.
* `expireTime`: Expiration time of the trigger in format: `2023-03-24T12:08:00`.
* `daysInterval`: Interval in number of days. For example: `1` or `3`.
* `delay`: Random time delay after the start time in which the trigger is hit. Use format `PT2H` for hours and `PT15M` for minutes.
* `userID`: Specify the user for which the trigger is set in format: `"DOMAIN\username"` for domain users, `username` for local system users and `""` for all users (requires admin privs if set for another user or all users).
* `repeatTask`: Set "Repeat task every x minutes/hours" option in format `PT2H` with a duration of `Indefinitely`.

## Usage
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" onetime <startTime> <(optional) repeatTask>`
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" daily <startTime> <(optional) expireTime> <(optional) daysInterval> <(optional) delay>`
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" logon <(optional) userID>`
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" startup <(optional) delay>`
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" lock <(optional) userID> <(optional) delay>`
* `addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" unlock <(optional) userID> <(optional) delay>`

## Examples
* `addtaskscheduler ExampleTask "" C:\Users\Public\Downloads\payload.exe "" onetime 2023-03-24T12:08:00 PT3H`
* `addtaskscheduler ExampleTask "" C:\Windows\System32\cmd.exe "/c C:\Windows\System32\calc.exe" daily 2023-03-24T12:08:00 2023-03-28T12:14:00 1 PT2H`
* `addtaskscheduler ExampleTask DB01.example.local C:\Users\Public\Downloads\payload.exe "" startup PT1M`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
