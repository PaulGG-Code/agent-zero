### security_workflow

orchestrate common security assessment workflows
automate multi-step security testing procedures
select "workflow_type" arg: "web_audit" "network_recon" "vulnerability_assessment" "quick_scan"
provide "target" arg with IP address, domain, or network range
use predefined workflows for common security assessments
can also use "custom_steps" for custom workflow definition
workflows include tool discovery, target validation, scanning, and analysis
essential for systematic security assessments and penetration testing
always validate target and scope before running workflows
usage:

1 web application security audit
~~~json
{
    "thoughts": [
        "Need to perform comprehensive web application security audit",
        "Will use predefined web_audit workflow",
        "This includes port scanning, directory enumeration, and vulnerability testing"
    ],
    "tool_name": "security_workflow",
    "tool_args": {
        "workflow_type": "web_audit",
        "target": "example.com"
    }
}
~~~

2 network reconnaissance
~~~json
{
    "thoughts": [
        "Need to perform network reconnaissance",
        "Will use network_recon workflow",
        "This includes host discovery, port scanning, and service enumeration"
    ],
    "tool_name": "security_workflow",
    "tool_args": {
        "workflow_type": "network_recon",
        "target": "192.168.1.0/24"
    }
}
~~~

3 vulnerability assessment
~~~json
{
    "thoughts": [
        "Need to perform vulnerability assessment",
        "Will use vulnerability_assessment workflow",
        "This includes comprehensive vulnerability scanning and analysis"
    ],
    "tool_name": "security_workflow",
    "tool_args": {
        "workflow_type": "vulnerability_assessment",
        "target": "target.com"
    }
}
~~~

4 quick security scan
~~~json
{
    "thoughts": [
        "Need quick initial reconnaissance",
        "Will use quick_scan workflow",
        "This provides basic port and service information"
    ],
    "tool_name": "security_workflow",
    "tool_args": {
        "workflow_type": "quick_scan",
        "target": "target.com"
    }
}
~~~

5 custom workflow
~~~json
{
    "thoughts": [
        "Need custom security workflow",
        "Will define specific steps for this assessment"
    ],
    "tool_name": "security_workflow",
    "tool_args": {
        "workflow_type": "custom",
        "target": "target.com",
        "custom_steps": [
            {
                "name": "Port Scan",
                "tool": "code_execution_tool",
                "args": {
                    "runtime": "terminal",
                    "code": "nmap -sV -p80,443 target.com"
                }
            },
            {
                "name": "Web Scan",
                "tool": "code_execution_tool",
                "args": {
                    "runtime": "terminal",
                    "code": "nikto -h http://target.com"
                }
            }
        ]
    }
}
~~~ 