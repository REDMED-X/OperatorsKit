# AddTaskScheduler
Start Windows credential prompt in an attempt to capture user credentials. Entered credentials are returned as output. The prompt is persistent so the victim can't cancel/close the prompt or enter an empty password. Any user attempt to do so is shown in the output. Finally, a timer is set on the prompt to make sure the beacon will return at some point.\n\n" .
	
>For the duration of the prompt, the beacon is occupied so set a reasonable timer. 

## Arguments
* `title`: a custom window title.
* `message`: a custom message set in the window.
* `timer`: number in seconds after how long the prompt should auto close. Default is set to 60.


## Usage
* `credprompt <title> <message> <(optional) time out>`


## Examples
* `credprompt "Microsoft Outlook" "Connecting to user@example.com" 30`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

