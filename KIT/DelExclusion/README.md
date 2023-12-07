# DelExclusion
Delete an exclusion from Windows Defender for a folder, file, process or extension.

>This operation requires elevated privileges. Furthermore, currently only Windows Defender exclusions are supported. Also, if you don't specify the full path to a folder, file or process, most likely the operation will return with the error message WBEM_E_NOT_FOUND. In general this condition effects deleting exclusions of type extension. 


## Arguments
* `<exclusion type>`: specify one of the following exclusion types you want to delete: `path` (file/folder), `process`, `extension`.
* `<exclusion data>`: specify the exclusion data/name that you want to delete.


## Usage
* `delexclusion <exclusion type> <exclusion data>`


## Example
* `delexclusion path C:\Users\Public\Downloads`
* `delexclusion process C:\Windows\System32\example.exe`
* `delexclusion extension *.xll`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
