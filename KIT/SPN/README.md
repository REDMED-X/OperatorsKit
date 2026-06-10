# SPN
Enumerate SPNs via multi-protocol discovery (ldap, ldaps, global catalog) or kerberoast a specific SPN.

>This BOF comes with a separate Python script to convert the returned Base64-encoded hash into a Hashcat-compatible format. The script automatically detects the type of hash that was returned and can be executed as follows: `python3 bof_to_hashcat.py <RAW_BASE64_STRING>`. 


## Usage
* `spn enum <ldap|ldaps|gc> <target> <dc>`
* `spn roast <target>`


## Arguments
* action: `enum` performs wildcard search to identify accounts with SPN set, `roast` requests the Kerberos ticket.
* protocol: [Only for enum] `ldap` (389), `ldaps` (636), or `gc` (Global Catalog 3268/3269)
* target: For `enum`, partial account name (use "" for all). For `roast`, full SPN string.
* dc: [Only for enum] The IP or Hostname of the specific Domain Controller to query.


## Examples
* `spn enum gc "" DC01.example.local`
* `spn enum ldaps sql DC01.example.local`
* `spn roast MSSQLSvc/sql01.example.local:1433` 


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

