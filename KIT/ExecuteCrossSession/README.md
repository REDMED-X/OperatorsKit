# ExecuteCrossSession
This BOF can execute a binary on disk in the context of another user. It achieves this through cross-session interaction using the IStandardActivator, ISpecialSystemProperties, and IHxHelpPaneServer COM interfaces. Consequently, process injection is not necessary to run code on behalf of another logged-on user.

>Similar to process injection, this technique requires local administrator privileges on the system to interact with another user's session.

## Acknowledgements
This BOF implementation is entirely based on the work of Michael Zhmailo. More information about his work can be found on his [blog](https://cicada-8.medium.com/process-injection-is-dead-long-live-ihxhelppaneserver-af8f20431b5d). Furthermore, a working POC named [IHxExec](https://github.com/CICADA8-Research/IHxExec/tree/main) can be found on his github.

## Arguments
* `<binary path>`: path to the binary you want to execute.
* `<session ID>`: specify the session ID of the user session in which the specified binary needs to be executed.

## Usage
* `executecrosssession <binary path> <session ID>`

## Examples
* `executecrosssession C:\\Windows\\System32\\calc.exe 2`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

