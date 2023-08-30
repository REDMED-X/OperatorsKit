# FindFile
Search for matching files based on a word, extention or keyword in the file content. Wildcards are supported.

>Keyword matching only works for text based files like .csv, .txt or .ps1 etc. So no MS Office files like .xlsx and .docs :(. 

## Arguments
* `<path to directory>`: specify a path to the directory from which to start searching (recursive searching supported).
* `<search pattern>`: specify a single word or extention to search for (support wildcards).
* `<keyword>`: leave empty OR specify a keyword to search for in text based files (support wildcards).

## Usage
* `findfile <path to directory> <search pattern> <(optional) keyword>`

## Examples
* `findfile C:\Users\RTO\Documents *.xlsx`
* `findfile C:\Users\RTO *login*.* username`
* `findfile C:\Users\RTO *.txt *pass*`

## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 
