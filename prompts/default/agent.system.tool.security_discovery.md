### security_tool_discovery

discover and report available security tools in kali environment
use to understand what security tools are available for use
select "action" arg: "discover" "check" "list"
use "discover" for comprehensive report of all tools
use "check" with "tool_name" to get details about specific tool
use "list" for simple list of available tools only
tool provides information about capabilities, usage examples, and availability
essential for planning security assessments and choosing appropriate tools
always run discovery first to understand available toolkit
usage:

1 discover all security tools
~~~json
{
    "thoughts": [
        "Need to understand what security tools are available",
        "Will discover all tools and their capabilities",
        "This will help plan the security assessment"
    ],
    "tool_name": "security_tool_discovery",
    "tool_args": {
        "action": "discover"
    }
}
~~~

2 check specific tool availability
~~~json
{
    "thoughts": [
        "Need to check if nmap is available",
        "Will verify nmap installation and get details"
    ],
    "tool_name": "security_tool_discovery",
    "tool_args": {
        "action": "check",
        "tool_name": "nmap"
    }
}
~~~

3 list available tools only
~~~json
{
    "thoughts": [
        "Need quick overview of available tools",
        "Will get simple list without detailed reports"
    ],
    "tool_name": "security_tool_discovery",
    "tool_args": {
        "action": "list"
    }
}
~~~ 