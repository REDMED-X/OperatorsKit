# AddFirewallRule
Add a new inbound or outbound firewall rule using COM.

>This operation requires elevated privileges. 

## Arguments
* `<direction>`: specify `in` for inbound or `out` for outbound.
* `<port>`: specify a single port (80) or port range (80-1000).
* `<rule name>`: specify the name of the new firewall rule.
* `<rule group>`: specify the name of the rule group OR leave empty.
* `<description>`: specify the description of the new rule OR leave empty.


## Usage
* `addfirewallrule <direction> <port> "<rule name>" "<rule group>" "<description>"`


## Example
* `addfirewallrule in 80 "ExampleRuleName1" "ExampleGroup1" "Test rule"`
* `addfirewallrule out 80-1000 "ExampleRuleName2"`


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

