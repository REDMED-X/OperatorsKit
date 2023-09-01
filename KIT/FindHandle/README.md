# FindHandle
Find `process` and `thread` handle types between processes.

## Options
**Search options:**
* `all`: list all processes with handles to all other processes.
* `h2p`: list all processes that have a handle to a specific process.
* `p2h`: list handles from a specific process to all other processes.

**Handle query options:**
* `proc`: search for PROCESS type handles.
* `thread`: search for THREAD type handles.

**Targeted search options:**
* `<pid>`: for both the `h2p` and `p2h` search options, specify the PID of the process your interested in.

## Usage
* `findhandle all <proc | thread>`
* `findhandle h2p <proc | thread> <pid>`
* `findhandle p2h <proc | thread> <pid>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
