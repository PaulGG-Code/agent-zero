import asyncio
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from python.helpers.tool import Tool, Response
from python.helpers.print_style import PrintStyle


@dataclass
class WorkflowStep:
    name: str
    description: str
    tool: str
    args: Dict
    required: bool = True
    depends_on: Optional[str] = None


class SecurityWorkflow(Tool):
    """Orchestrates common security assessment workflows"""
    
    # Predefined workflows
    WORKFLOWS = {
        "web_audit": {
            "name": "Web Application Security Audit",
            "description": "Comprehensive web application security assessment",
            "steps": [
                WorkflowStep(
                    name="Tool Discovery",
                    description="Discover available security tools",
                    tool="security_tool_discovery",
                    args={"action": "discover"}
                ),
                WorkflowStep(
                    name="Target Validation",
                    description="Validate target and scope",
                    tool="knowledge_tool",
                    args={"query": "web application security testing scope and authorization"}
                ),
                WorkflowStep(
                    name="Port Scan",
                    description="Scan for open ports and services",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sV -sC -p80,443,8080,8443 {target}"}
                ),
                WorkflowStep(
                    name="Web Directory Scan",
                    description="Scan for hidden directories and files",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "dirb http://{target} /usr/share/dirb/wordlists/common.txt"}
                ),
                WorkflowStep(
                    name="Nikto Scan",
                    description="Web server vulnerability scan",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nikto -h http://{target}"}
                ),
                WorkflowStep(
                    name="SQL Injection Test",
                    description="Test for SQL injection vulnerabilities",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "sqlmap -u 'http://{target}/page?id=1' --batch --level=1"}
                )
            ]
        },
        "network_recon": {
            "name": "Network Reconnaissance",
            "description": "Comprehensive network reconnaissance and mapping",
            "steps": [
                WorkflowStep(
                    name="Tool Discovery",
                    description="Discover available security tools",
                    tool="security_tool_discovery",
                    args={"action": "discover"}
                ),
                WorkflowStep(
                    name="Network Discovery",
                    description="Discover live hosts on network",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sn {network_range}"}
                ),
                WorkflowStep(
                    name="Port Scanning",
                    description="Scan for open ports on discovered hosts",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sS -sV -O {target_hosts}"}
                ),
                WorkflowStep(
                    name="Service Enumeration",
                    description="Enumerate services and versions",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sV -sC -p- {target_hosts}"}
                ),
                WorkflowStep(
                    name="Vulnerability Scan",
                    description="Scan for known vulnerabilities",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap --script vuln {target_hosts}"}
                )
            ]
        },
        "vulnerability_assessment": {
            "name": "Vulnerability Assessment",
            "description": "Comprehensive vulnerability assessment",
            "steps": [
                WorkflowStep(
                    name="Tool Discovery",
                    description="Discover available security tools",
                    tool="security_tool_discovery",
                    args={"action": "discover"}
                ),
                WorkflowStep(
                    name="Target Analysis",
                    description="Analyze target for assessment scope",
                    tool="knowledge_tool",
                    args={"query": "vulnerability assessment methodology and best practices"}
                ),
                WorkflowStep(
                    name="Initial Scan",
                    description="Perform initial vulnerability scan",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sV -sC --script vuln {target}"}
                ),
                WorkflowStep(
                    name="Service Analysis",
                    description="Analyze specific services for vulnerabilities",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sV -sC -p80,443,22,21,23,25,53,110,143,993,995 {target}"}
                ),
                WorkflowStep(
                    name="Web Vulnerability Scan",
                    description="Scan web services for vulnerabilities",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nikto -h http://{target}"}
                )
            ]
        },
        "quick_scan": {
            "name": "Quick Security Scan",
            "description": "Quick security assessment for initial reconnaissance",
            "steps": [
                WorkflowStep(
                    name="Tool Discovery",
                    description="Discover available security tools",
                    tool="security_tool_discovery",
                    args={"action": "list"}
                ),
                WorkflowStep(
                    name="Basic Port Scan",
                    description="Quick port scan to identify services",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -F {target}"}
                ),
                WorkflowStep(
                    name="Service Detection",
                    description="Detect service versions",
                    tool="code_execution_tool",
                    args={"runtime": "terminal", "code": "nmap -sV {target}"}
                )
            ]
        }
    }

    async def execute(self, **kwargs) -> Response:
        """Execute security workflow"""
        
        workflow_type = self.args.get("workflow_type")
        target = self.args.get("target")
        custom_steps = self.args.get("custom_steps", [])
        
        if not workflow_type:
            return Response(message="Error: workflow_type required", break_loop=False)
        
        if workflow_type not in self.WORKFLOWS and not custom_steps:
            available_workflows = ", ".join(self.WORKFLOWS.keys())
            return Response(message=f"Unknown workflow: {workflow_type}. Available: {available_workflows}", break_loop=False)
        
        if workflow_type in self.WORKFLOWS:
            return await self._execute_predefined_workflow(workflow_type, target)
        else:
            return await self._execute_custom_workflow(custom_steps, target)

    async def _execute_predefined_workflow(self, workflow_type: str, target: str) -> Response:
        """Execute a predefined workflow"""
        workflow = self.WORKFLOWS[workflow_type]
        
        report = f"# {workflow['name']}\n\n"
        report += f"**Description**: {workflow['description']}\n\n"
        report += f"**Target**: {target}\n\n"
        report += f"**Status**: Starting workflow...\n\n"
        
        # Execute each step
        results = []
        for i, step in enumerate(workflow['steps'], 1):
            report += f"## Step {i}: {step.name}\n\n"
            report += f"**Description**: {step.description}\n\n"
            
            try:
                # Replace placeholders in args
                step_args = self._replace_placeholders(step.args, target)
                
                # Execute the step
                step_result = await self._execute_workflow_step(step.tool, step_args)
                results.append({
                    "step": step.name,
                    "tool": step.tool,
                    "status": "success",
                    "result": step_result
                })
                
                report += f"**Status**: ✅ Completed\n\n"
                report += f"**Result**: {step_result[:500]}...\n\n" if len(step_result) > 500 else f"**Result**: {step_result}\n\n"
                
            except Exception as e:
                results.append({
                    "step": step.name,
                    "tool": step.tool,
                    "status": "failed",
                    "error": str(e)
                })
                
                report += f"**Status**: ❌ Failed\n\n"
                report += f"**Error**: {str(e)}\n\n"
                
                if step.required:
                    report += f"**Workflow stopped due to required step failure**\n\n"
                    break
        
        # Generate summary
        report += self._generate_workflow_summary(results, workflow_type)
        
        return Response(message=report, break_loop=False)

    async def _execute_custom_workflow(self, custom_steps: List[Dict], target: str) -> Response:
        """Execute a custom workflow"""
        report = f"# Custom Security Workflow\n\n"
        report += f"**Target**: {target}\n\n"
        report += f"**Steps**: {len(custom_steps)}\n\n"
        
        results = []
        for i, step in enumerate(custom_steps, 1):
            report += f"## Step {i}: {step.get('name', f'Step {i}')}\n\n"
            
            try:
                tool = step.get('tool')
                args = step.get('args', {})
                
                if not tool:
                    raise ValueError("Tool not specified in custom step")
                
                # Replace placeholders
                args = self._replace_placeholders(args, target)
                
                # Execute step
                step_result = await self._execute_workflow_step(tool, args)
                results.append({
                    "step": step.get('name', f'Step {i}'),
                    "tool": tool,
                    "status": "success",
                    "result": step_result
                })
                
                report += f"**Status**: ✅ Completed\n\n"
                report += f"**Result**: {step_result[:500]}...\n\n" if len(step_result) > 500 else f"**Result**: {step_result}\n\n"
                
            except Exception as e:
                results.append({
                    "step": step.get('name', f'Step {i}'),
                    "tool": step.get('tool', 'unknown'),
                    "status": "failed",
                    "error": str(e)
                })
                
                report += f"**Status**: ❌ Failed\n\n"
                report += f"**Error**: {str(e)}\n\n"
        
        # Generate summary
        report += self._generate_workflow_summary(results, "custom")
        
        return Response(message=report, break_loop=False)

    async def _execute_workflow_step(self, tool_name: str, args: Dict) -> str:
        """Execute a single workflow step"""
        # Get the tool instance
        tool = self.agent.get_tool(tool_name, None, args, "")
        
        if not tool:
            raise ValueError(f"Tool '{tool_name}' not found")
        
        # Execute the tool
        response = await tool.execute()
        return response.message

    def _replace_placeholders(self, args: Dict, target: str) -> Dict:
        """Replace placeholders in arguments with actual values"""
        args_str = json.dumps(args)
        args_str = args_str.replace("{target}", target)
        args_str = args_str.replace("{network_range}", target)  # For network scans
        args_str = args_str.replace("{target_hosts}", target)   # For host scans
        return json.loads(args_str)

    def _generate_workflow_summary(self, results: List[Dict], workflow_type: str) -> str:
        """Generate a summary of workflow execution"""
        successful_steps = [r for r in results if r['status'] == 'success']
        failed_steps = [r for r in results if r['status'] == 'failed']
        
        summary = f"# Workflow Summary\n\n"
        summary += f"**Workflow Type**: {workflow_type}\n"
        summary += f"**Total Steps**: {len(results)}\n"
        summary += f"**Successful**: {len(successful_steps)}\n"
        summary += f"**Failed**: {len(failed_steps)}\n"
        summary += f"**Success Rate**: {(len(successful_steps) / len(results) * 100):.1f}%\n\n"
        
        if successful_steps:
            summary += f"## Successful Steps\n\n"
            for step in successful_steps:
                summary += f"- ✅ {step['step']} ({step['tool']})\n"
            summary += "\n"
        
        if failed_steps:
            summary += f"## Failed Steps\n\n"
            for step in failed_steps:
                summary += f"- ❌ {step['step']} ({step['tool']}): {step.get('error', 'Unknown error')}\n"
            summary += "\n"
        
        summary += f"## Recommendations\n\n"
        if failed_steps:
            summary += f"- Review failed steps and error messages\n"
            summary += f"- Verify tool availability and configuration\n"
            summary += f"- Check target accessibility and permissions\n"
            summary += f"- Consider running individual steps manually\n"
        else:
            summary += f"- All steps completed successfully\n"
            summary += f"- Review results for security findings\n"
            summary += f"- Document findings and recommendations\n"
            summary += f"- Plan follow-up actions based on results\n"
        
        return summary

    def get_log_object(self):
        return self.agent.context.log.log(
            type="security_workflow",
            heading=f"{self.agent.agent_name}: Using tool '{self.name}'",
            content="",
            kvps=self.args,
        )

    async def after_execution(self, response, **kwargs):
        self.agent.hist_add_tool_result(self.name, response.message) 