# HideFile
Hide a directory or file from plain sight by modifying the attributes and set them to systemfile + hidden.

## Options
* `dir`: set this option if you want to modify the attributes of a directory.
* `file`: set this option if you want to modify the attributes of a file.
* `<path to dir/file>`: path to the directory or file that you want to hide.

## Usage
* `hidefile <dir | file> <path to dir/file>`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
