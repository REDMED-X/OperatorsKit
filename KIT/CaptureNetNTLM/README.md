# CaptureNetNTLM
Capture the NetNTLMv2 hash of the current user. This is done by simulating a NTLM authentication exchange between a client and server to capture the NetNTLMv2 hash.


## Usage
* `capturenetntlm`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 


## Credits
The code in this BOF is heaviliy based on the [GetNTLMChallenge](https://github.com/leechristensen/GetNTLMChallenge/tree/master) project from Lee Christensen. 