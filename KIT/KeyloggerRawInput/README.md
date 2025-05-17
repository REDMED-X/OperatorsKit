# KeyloggerRawInput
During the first run, the BOF-keylogger registers for raw input using the RegisterRawInputDevices API and Windows begins capturing every keystroke into its internal raw-input buffer, converting them into WM_INPUT messages and posting them to the beacon thread's message queue. Each run thereafter when the keylogger calls PeekMessageA() in a loop, it will drain and process all pending WM_INPUT messages from the raw-input buffer and print the results to the beacon console.

>Between each run, Windows continues to queue up to 10.000 WM_INPUT messages on the thread - any further keystrokes beyond that are dropped. Therefore, it is recommended to run the BOF atleast every few hours to drain and process the message queue. 

## Arguments
* `<option>`: specify one of the following options: `run` (start the keylogger or collect keystroke results), or `stop` (stop the keylogger).\n\n" .
	

## Usage
* `keyloggerrawinput <option>`

## Examples
* `keyloggerrawinput run`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


