# AddTaskScheduler
This tool can create/update a scheduled task on the current system or a remote host. 

>As a rule of thumb, setting a scheduled task on a remote host or for any other user but yourself, requires elevated privileges or credentials (in the case of the latter). Furthermore, the tool returns error codes if the operation fails. The most common error codes are: 80070005 (not enough privileges) and 80041318/80041319 (most likely you made a typo in one of the input fields). 

## Supported trigger options
* `onetime`: Create task with trigger "On a schedule: one time".
* `daily`: Create task with trigger "On a schedule: daily."
* `logon`: Create task with trigger "At log on" (requires elevated privileges if set for another user or all users).
* `startup`: Create task with trigger "At startup" (requires elevated privileges).
* `lock`: Create task with trigger "On workstation lock" (requires elevated privileges if set for another user or all users).
* `unlock`: Create task with trigger "On workstation unlock" (requires elevated privileges if set for another user or all users).

## Supported user context (security) options
* `current`: Run the task as the current user account only when this user is logged on.
* `current+`: Run the task with the highest privileges as the current user account only when this user is logged on.
* `creds`: Run the task as the specified user account whether the user is logged on or not (requires plaintext password).
* `creds+`: Run the task with the highest privileges as the specified user account whether the user is logged on or not (requires plaintext password).
* `system`: Run the task as SYSTEM whether the user is logged on or not.

## Mandatory arguments
* `taskName`: The name of the scheduled task.
* `hostName`: The FQDN/hostname of the remote host or \"\" for the current host. 
* `contextType`: Under which user context (security option) the task is set. Supported options: `current`, `current+`, `creds`, `creds+`, `system`.
* `programPath`: Path to the program that you want to run like.
* `programArguments`: Arguments that you want to pass to the program (specify `""` to leave it empty).
* `triggerType`: The trigger that signals the execution. Supported options: `onetime`, `daily`, `logon`, `startup`, `lock`, `unlock`. 

## Optional arguments
* `startTime`: Start time of the trigger in format: `2023-03-24T12:08:00`.
* `expireTime`: Expiration time of the trigger in format: `2023-03-24T12:08:00`.
* `daysInterval`: Interval in number of days. For example: `1` or `3`.
* `delay`: Random time delay after the start time in which the trigger is hit. Use format `PT2H` for hours and `PT15M` for minutes.
* `userID`: User(s) that trigger the task. For domain users specify "DOMAIN\username" , for local system users specify "username" and for all users specify "" (empty).
* `repeatTask`: Set "Repeat task every x minutes/hours" option in format `PT2H` with a duration of `Indefinitely`.
* `userName`: Run task as this user account (must be used in combination with "userPassword".
* `userPassword`: Password for account specified under "userName".

## Usage
* OneTime trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" onetime <startTime> <(optional) repeatTask> <(optional) userName> <(optional) userPassword>`
* Daily trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" daily <startTime> <(optional) expireTime> <(optional) daysInterval> <(optional) delay> <(optional) userName> <(optional) userPassword>`
* Logon trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" logon <(optional) userID> <(optional) userName> <(optional) userPassword>`
* Startup trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" startup <(optional) delay> <(optional) userName> <(optional) userPassword>`
* Lock trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" lock <(optional) userID> <(optional) delay> <(optional) userName> <(optional) userPassword>`
* Unlock trigger: `addtaskscheduler <taskName> <(optional) hostName> <contextType> <programPath> "<(optional) programArguments>" unlock <(optional) userID> <(optional) delay> <(optional) userName> <(optional) userPassword`

## Examples
* Set scheduled task on the local host as the current user with trigger option onetime: `addtaskscheduler TestTask "" current C:\Windows\System32\cmd.exe "/c C:\Windows\System32\calc.exe" onetime 2023-03-24T12:08:00 PT2H`
* Set scheduled task on the local host as the user John using credentials that runs with the highest privileges and trigger option onetime: `addtaskscheduler TestTask "" creds+ C:\Users\John\Desktop\program.exe "" onetime 2023-03-24T12:08:00 PT2H example.local\john Welcome01`
* Set scheduled task on the local host as SYSTEM with trigger option startup: `addtaskscheduler TestTask "" system C:\Windows\System32\cmd.exe "/c C:\Windows\System32\calc.exe" startup PT10M`
* Set scheduled task on a remote host as the current user that runs with the highest privileges and trigger option unlock: `addtaskscheduler TestTask WS01.example.local current+ C:\Users\John\Desktop\program.exe "" unlock`
* Set scheduled task on a remote host as the user John using credentials with trigger option logon: `addtaskscheduler TestTask WS01.example.local creds C:\Users\John\Desktop\program.exe "" logon "" example.local\john Welcome01!`
* Set scheduled task on a remote host as SYSTEM with trigger option daily: `addtaskscheduler TestTask WS01.example.local system C:\Windows\System32\cmd.exe "/c C:\Windows\System32\calc.exe" daily 2023-03-24T12:08:00 2023-03-28T12:14:00 3 PT5M`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

