# BlindEventlog
Blind Eventlog by suspending its threads. This technique requires elevated privileges.

>Be aware that all events, from the period the threads were suspended, will be pushed to Eventlog the moment the threads are resumed.

## Options
* `suspend`: find and suspend all Eventlog threads and disrupt its functionality.
* `resume`: find and resume all Eventlog threads and restore its functionality.

## Usage
* `blindeventlog <suspend | resume>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
