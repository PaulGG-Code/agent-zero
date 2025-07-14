import asyncio
import subprocess
import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from python.helpers.tool import Tool, Response
from python.helpers.print_style import PrintStyle


@dataclass
class SecurityTool:
    name: str
    path: str
    version: str
    description: str
    category: str
    capabilities: List[str]
    usage_example: str
    is_available: bool = True


class SecurityToolDiscovery(Tool):
    """Discovers and provides information about available security tools in the Kali environment"""
    
    # Common security tools to check
    SECURITY_TOOLS = {
        "nmap": {
            "path": "/usr/bin/nmap",
            "category": "network_scanner",
            "description": "Network discovery and security auditing",
            "capabilities": ["port_scanning", "service_detection", "os_detection", "vulnerability_scanning"],
            "usage_example": "nmap -sV -sC target.com"
        },
        "masscan": {
            "path": "/usr/bin/masscan",
            "category": "network_scanner",
            "description": "Fast port scanner",
            "capabilities": ["fast_port_scanning", "large_network_scanning"],
            "usage_example": "masscan -p80,443,22 target.com"
        },
        "nikto": {
            "path": "/usr/bin/nikto",
            "category": "web_scanner",
            "description": "Web server scanner",
            "capabilities": ["web_vulnerability_scanning", "server_misconfiguration_detection"],
            "usage_example": "nikto -h target.com"
        },
        "dirb": {
            "path": "/usr/bin/dirb",
            "category": "web_scanner",
            "description": "Web content scanner",
            "capabilities": ["directory_bruteforcing", "file_discovery"],
            "usage_example": "dirb http://target.com /usr/share/dirb/wordlists/common.txt"
        },
        "sqlmap": {
            "path": "/usr/bin/sqlmap",
            "category": "web_exploitation",
            "description": "SQL injection testing tool",
            "capabilities": ["sql_injection_detection", "database_enumeration", "data_extraction"],
            "usage_example": "sqlmap -u 'http://target.com/page?id=1'"
        },
        "hydra": {
            "path": "/usr/bin/hydra",
            "category": "password_attack",
            "description": "Network logon cracker",
            "capabilities": ["brute_force_attacks", "credential_testing"],
            "usage_example": "hydra -l admin -P wordlist.txt target.com ssh"
        },
        "john": {
            "path": "/usr/bin/john",
            "category": "password_attack",
            "description": "Password cracker",
            "capabilities": ["password_cracking", "hash_analysis"],
            "usage_example": "john --wordlist=wordlist.txt hashfile.txt"
        },
        "aircrack-ng": {
            "path": "/usr/bin/aircrack-ng",
            "category": "wireless_security",
            "description": "Wireless network security suite",
            "capabilities": ["wifi_auditing", "packet_capture", "wep_wpa_cracking"],
            "usage_example": "aircrack-ng -w wordlist.txt capture.cap"
        },
        "metasploit": {
            "path": "/usr/bin/msfconsole",
            "category": "exploitation",
            "description": "Penetration testing framework",
            "capabilities": ["exploit_development", "payload_generation", "post_exploitation"],
            "usage_example": "msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; run'"
        },
        "wireshark": {
            "path": "/usr/bin/wireshark",
            "category": "network_analysis",
            "description": "Network protocol analyzer",
            "capabilities": ["packet_analysis", "traffic_inspection", "protocol_decoding"],
            "usage_example": "wireshark -i eth0 -k"
        }
    }

    async def execute(self, **kwargs) -> Response:
        """Discover and report available security tools"""
        
        action = self.args.get("action", "discover")
        
        if action == "discover":
            return await self._discover_tools()
        elif action == "check":
            tool_name = self.args.get("tool_name")
            if tool_name:
                return await self._check_specific_tool(tool_name)
            else:
                return Response(message="Error: tool_name required for check action", break_loop=False)
        elif action == "list":
            return await self._list_available_tools()
        else:
            return Response(message=f"Unknown action: {action}. Use 'discover', 'check', or 'list'", break_loop=False)

    async def _discover_tools(self) -> Response:
        """Discover all available security tools"""
        discovered_tools = []
        unavailable_tools = []
        
        for tool_name, tool_info in self.SECURITY_TOOLS.items():
            tool = await self._check_tool_availability(tool_name, tool_info)
            if tool.is_available:
                discovered_tools.append(tool)
            else:
                unavailable_tools.append(tool)
        
        # Generate comprehensive report
        report = self._generate_discovery_report(discovered_tools, unavailable_tools)
        
        return Response(message=report, break_loop=False)

    async def _check_specific_tool(self, tool_name: str) -> Response:
        """Check availability and details of a specific tool"""
        if tool_name not in self.SECURITY_TOOLS:
            return Response(message=f"Unknown tool: {tool_name}", break_loop=False)
        
        tool_info = self.SECURITY_TOOLS[tool_name]
        tool = await self._check_tool_availability(tool_name, tool_info)
        
        report = self._generate_tool_report(tool)
        return Response(message=report, break_loop=False)

    async def _list_available_tools(self) -> Response:
        """List only available tools with basic info"""
        available_tools = []
        
        for tool_name, tool_info in self.SECURITY_TOOLS.items():
            tool = await self._check_tool_availability(tool_name, tool_info)
            if tool.is_available:
                available_tools.append(tool)
        
        report = self._generate_available_tools_list(available_tools)
        return Response(message=report, break_loop=False)

    async def _check_tool_availability(self, tool_name: str, tool_info: Dict) -> SecurityTool:
        """Check if a tool is available and get its version"""
        path = tool_info["path"]
        version = "Unknown"
        is_available = False
        
        try:
            # Check if tool exists
            if os.path.exists(path):
                is_available = True
                # Try to get version
                try:
                    result = subprocess.run([path, "--version"], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        version = result.stdout.strip().split('\n')[0]
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    # Try alternative version flags
                    try:
                        result = subprocess.run([path, "-v"], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            version = result.stdout.strip().split('\n')[0]
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                        version = "Available (version unknown)"
            else:
                # Check if tool is available in PATH
                try:
                    result = subprocess.run(["which", tool_name], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        is_available = True
                        version = "Available in PATH"
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass
                    
        except Exception as e:
            version = f"Error checking: {str(e)}"
        
        return SecurityTool(
            name=tool_name,
            path=path,
            version=version,
            description=tool_info["description"],
            category=tool_info["category"],
            capabilities=tool_info["capabilities"],
            usage_example=tool_info["usage_example"],
            is_available=is_available
        )

    def _generate_discovery_report(self, discovered_tools: List[SecurityTool], 
                                 unavailable_tools: List[SecurityTool]) -> str:
        """Generate a comprehensive discovery report"""
        report = "# Security Tools Discovery Report\n\n"
        
        # Summary
        report += f"## Summary\n"
        report += f"- **Available Tools**: {len(discovered_tools)}\n"
        report += f"- **Unavailable Tools**: {len(unavailable_tools)}\n"
        report += f"- **Total Checked**: {len(discovered_tools) + len(unavailable_tools)}\n\n"
        
        # Available tools by category
        if discovered_tools:
            report += "## Available Security Tools\n\n"
            
            # Group by category
            categories = {}
            for tool in discovered_tools:
                if tool.category not in categories:
                    categories[tool.category] = []
                categories[tool.category].append(tool)
            
            for category, tools in categories.items():
                category_name = category.replace('_', ' ').title()
                report += f"### {category_name}\n\n"
                
                for tool in tools:
                    report += f"#### {tool.name}\n"
                    report += f"- **Description**: {tool.description}\n"
                    report += f"- **Version**: {tool.version}\n"
                    report += f"- **Capabilities**: {', '.join(tool.capabilities)}\n"
                    report += f"- **Usage Example**: `{tool.usage_example}`\n\n"
        
        # Unavailable tools
        if unavailable_tools:
            report += "## Unavailable Tools\n\n"
            report += "The following tools were not found in the current environment:\n\n"
            
            for tool in unavailable_tools:
                report += f"- **{tool.name}**: {tool.description}\n"
                report += f"  - Expected path: {tool.path}\n"
                report += f"  - Category: {tool.category.replace('_', ' ').title()}\n\n"
        
        # Recommendations
        report += "## Recommendations\n\n"
        if discovered_tools:
            report += "### For Network Assessment\n"
            network_tools = [t for t in discovered_tools if 'network' in t.category]
            if network_tools:
                report += f"Use: {', '.join([t.name for t in network_tools])}\n\n"
            
            report += "### For Web Application Testing\n"
            web_tools = [t for t in discovered_tools if 'web' in t.category]
            if web_tools:
                report += f"Use: {', '.join([t.name for t in web_tools])}\n\n"
            
            report += "### For Exploitation\n"
            exploit_tools = [t for t in discovered_tools if 'exploitation' in t.category]
            if exploit_tools:
                report += f"Use: {', '.join([t.name for t in exploit_tools])}\n\n"
        
        return report

    def _generate_tool_report(self, tool: SecurityTool) -> str:
        """Generate detailed report for a specific tool"""
        report = f"# {tool.name.upper()} Tool Report\n\n"
        
        report += f"## Status\n"
        status = "✅ Available" if tool.is_available else "❌ Unavailable"
        report += f"- **Status**: {status}\n"
        report += f"- **Path**: {tool.path}\n"
        report += f"- **Version**: {tool.version}\n\n"
        
        report += f"## Description\n"
        report += f"{tool.description}\n\n"
        
        report += f"## Category\n"
        report += f"{tool.category.replace('_', ' ').title()}\n\n"
        
        report += f"## Capabilities\n"
        for capability in tool.capabilities:
            report += f"- {capability.replace('_', ' ').title()}\n"
        report += "\n"
        
        report += f"## Usage Example\n"
        report += f"```bash\n{tool.usage_example}\n```\n\n"
        
        if tool.is_available:
            report += f"## Next Steps\n"
            report += f"1. Verify the tool works in your environment\n"
            report += f"2. Review the tool's documentation\n"
            report += f"3. Test with safe targets first\n"
            report += f"4. Ensure proper authorization before use\n"
        
        return report

    def _generate_available_tools_list(self, tools: List[SecurityTool]) -> str:
        """Generate a simple list of available tools"""
        report = "# Available Security Tools\n\n"
        
        for tool in tools:
            report += f"## {tool.name}\n"
            report += f"- **Category**: {tool.category.replace('_', ' ').title()}\n"
            report += f"- **Description**: {tool.description}\n"
            report += f"- **Usage**: `{tool.usage_example}`\n\n"
        
        return report

    def get_log_object(self):
        return self.agent.context.log.log(
            type="security_discovery",
            heading=f"{self.agent.agent_name}: Using tool '{self.name}'",
            content="",
            kvps=self.args,
        )

    async def after_execution(self, response, **kwargs):
        self.agent.hist_add_tool_result(self.name, response.message) 