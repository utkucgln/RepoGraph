"""
Security analyzer agent.

This module provides an agent that performs comprehensive security
analysis of repositories to identify vulnerabilities and issues.
"""

import os
import re
import logging
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.agent_base import Agent
from src.utils.file_utils import read_file, get_file_type
from src.utils.security_patterns import SECURITY_PATTERNS, scan_content_for_security_issues
from src.utils.logging_utils import log_execution_time, StatusLogger


class SecurityAnalyzerAgent(Agent):
    """Agent for performing comprehensive security analysis.

    This agent analyzes repository files for security vulnerabilities
    and issues, providing detailed findings and recommendations.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the security analyzer agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and perform security analysis.

        Args:
            state: Current state containing repository information

        Returns:
            Updated state with security analysis report
        """
        self.log_info("Security Agent: Starting security analysis")

        # Get file list and repository path
        file_list = self._get_file_list(state)
        repo_path = self._extract_repo_path(state)

        if not file_list:
            self.log_error("Security Agent: No file list found in state")
            error_msg = "No file list found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        if not repo_path:
            self.log_error("Security Agent: No repository path found in state")
            error_msg = "No repository path found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get context information
        context = self._gather_context(state)

        # Select files to analyze
        files_to_analyze = self._select_files_to_analyze(file_list, context)
        self.log_info(f"Selected {len(files_to_analyze)} files for security analysis")

        # Scan files for security issues
        security_findings = self._scan_files_for_security_issues(files_to_analyze, repo_path)
        self.log_info(f"Found security issues in {len(security_findings)} files")

        # Analyze and categorize findings
        analysis = self._analyze_security_findings(security_findings, context)

        # Generate the security report
        report = self._generate_security_report(security_findings, analysis, context)

        # Add report to state
        state = self.add_message_to_state(
            state,
            report,
            "system",
            "security_report"
        )

        # Save report to file if output directory exists
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_path = os.path.join(output_dir, "security_analysis.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        self.log_info(f"Report saved to {report_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Security Agent: Analysis complete")
        return state

    def _get_file_list(self, state: Dict[str, Any]) -> List[str]:
        """Get the file list from the state.

        Args:
            state: Current state

        Returns:
            List of file paths
        """
        # First try to get from file_list message
        file_list_message = self.get_last_message_by_name(state, "file_list")
        if file_list_message:
            content = file_list_message.get("content", "")
            if "Files:" in content:
                return content.split("Files:")[1].strip().split("\n")

        # If repository object exists, get files from there
        repository = state.get("repository")
        if repository and hasattr(repository, "all_files"):
            return list(repository.all_files.keys())

        return []

    def _extract_repo_path(self, state: Dict[str, Any]) -> Optional[str]:
        """Extract the repository path from the state.

        Args:
            state: Current state

        Returns:
            Repository path if found, None otherwise
        """
        # First, check if repo_path is directly in the state
        if "repo_path" in state:
            return state["repo_path"]

        # Then check messages for a path specification
        for message in state.get("messages", []):
            if isinstance(message, dict):
                content = message.get("content", "")
            else:
                content = getattr(message, "content", "")

            # Look for "Path:" in the message
            if "Path:" in content:
                parts = content.split("Path:")
                if len(parts) > 1:
                    path = parts[1].strip()
                    # If there are newlines, take just the first line
                    if "\n" in path:
                        path = path.split("\n")[0].strip()
                    return path

        return None

    def _gather_context(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Gather repository context for security analysis.

        Args:
            state: Current state

        Returns:
            Dictionary with context information
        """
        context = {}

        # Get file descriptions
        file_descriptions_message = self.get_last_message_by_name(state, "file_descriptions")
        if file_descriptions_message:
            content = file_descriptions_message.get("content", "")
            context["file_descriptions"] = content

        # Get repository report
        report_message = self.get_last_message_by_name(state, "report")
        if report_message:
            content = report_message.get("content", "")
            context["report"] = content

        # Get critical method report
        critical_method_message = self.get_last_message_by_name(state, "critical_method_report")
        if critical_method_message:
            content = critical_method_message.get("content", "")
            context["critical_method_report"] = content

            # Extract critical methods
            critical_methods = self._extract_critical_methods(content)
            if critical_methods:
                context["critical_methods"] = critical_methods

        return context

    def _extract_critical_methods(self, critical_method_report: str) -> List[Dict[str, Any]]:
        """Extract critical method information from the report.

        Args:
            critical_method_report: Critical method report content

        Returns:
            List of critical method dictionaries
        """
        critical_methods = []

        # Extract method blocks
        method_blocks = re.finditer(r'### `([^`]+)`\n\n(.*?)(?=###|\Z)',
                                    critical_method_report, re.DOTALL)

        for match in method_blocks:
            method_name = match.group(1)
            method_content = match.group(2)

            # Extract security categories
            categories_match = re.search(r'\*\*Security Categories:\*\* (.*?)\n', method_content)
            categories = []
            if categories_match:
                categories = [c.strip() for c in categories_match.group(1).split(',')]

            # Extract file and line info
            file_matches = re.finditer(r'\*\*File:\*\* (.*?), \*\*Line:\*\* (\d+)', method_content)
            locations = []

            for file_match in file_matches:
                file_path = file_match.group(1)
                line_no = file_match.group(2)
                locations.append({"file": file_path, "line": line_no})

            critical_methods.append({
                "name": method_name,
                "categories": categories,
                "locations": locations
            })

        return critical_methods

    def _select_files_to_analyze(self, file_list: List[str],
                                 context: Dict[str, Any]) -> List[str]:
        """Select files to analyze for security issues.

        Args:
            file_list: List of all files
            context: Context information

        Returns:
            List of files to analyze
        """
        # Define high-risk extensions
        high_risk_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go', '.java',
            '.cs', '.c', '.cpp', '.scala', '.rs', '.sh', '.bash'
        }

        # Define high-risk file patterns
        high_risk_patterns = [
            r'auth', r'login', r'password', r'token', r'session', r'user', r'admin',
            r'security', r'permission', r'role', r'access', r'api', r'controller',
            r'route', r'input', r'validate', r'sanitize', r'sql', r'query', r'database',
            r'encrypt', r'decrypt', r'hash', r'crypt', r'secret', r'key', r'cert',
            r'config', r'settings', r'env', r'environment'
        ]

        # Get critical method files
        critical_method_files = set()
        if "critical_methods" in context:
            for method in context["critical_methods"]:
                for location in method.get("locations", []):
                    critical_method_files.add(location.get("file", ""))

        # Prioritize files
        high_risk_files = []
        medium_risk_files = []
        low_risk_files = []

        for file_path in file_list:
            # Skip binary files and very large files
            if file_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                                   '.woff', '.woff2', '.ttf', '.eot', '.otf', '.pdf',
                                   '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
                                   '.class', '.pyc', '.pyo', '.o', '.obj')):
                continue

            # Skip node_modules, virtual environments, and other non-source directories
            if any(part in file_path for part in ['/node_modules/', '/venv/', '/.venv/',
                                                  '/env/', '/dist/', '/build/', '/.git/',
                                                  '/vendor/', '/third_party/', '/third-party/']):
                continue

            # Critical method files are high risk
            if file_path in critical_method_files:
                high_risk_files.append(file_path)
                continue

            # Check extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext in high_risk_extensions:
                # Check for high-risk patterns in filename
                filename = os.path.basename(file_path).lower()
                if any(re.search(pattern, filename, re.IGNORECASE) for pattern in high_risk_patterns):
                    high_risk_files.append(file_path)
                else:
                    medium_risk_files.append(file_path)
            else:
                # Check if it might be a configuration or other sensitive file
                filename = os.path.basename(file_path).lower()
                if any(filename.startswith(name) for name in [
                    'config', 'settings', '.env', 'docker', 'kubernetes', 'k8s',
                    'nginx', 'apache', 'web.config', 'app.yaml', 'secret'
                ]):
                    medium_risk_files.append(file_path)
                else:
                    low_risk_files.append(file_path)

        # Limit number of files to analyze
        max_files = 100

        # Take all high risk files, then medium, then low until we reach the limit
        selected_files = high_risk_files.copy()

        if len(selected_files) < max_files:
            remaining = max_files - len(selected_files)
            selected_files.extend(medium_risk_files[:remaining])

        if len(selected_files) < max_files:
            remaining = max_files - len(selected_files)
            selected_files.extend(low_risk_files[:remaining])

        return selected_files

    def _scan_files_for_security_issues(self, files: List[str],
                                        repo_path: str) -> Dict[str, Dict[str, Any]]:
        """Scan files for security issues.

        Args:
            files: List of files to scan
            repo_path: Repository path

        Returns:
            Dictionary mapping file paths to security findings
        """
        security_findings = {}
        status_logger = StatusLogger(len(files), "security scan")

        # Process files in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for file_path in files:
                full_path = os.path.join(repo_path, file_path)
                future = executor.submit(self._scan_file, file_path, full_path)
                futures[future] = file_path

            # Process results as they complete
            for i, future in enumerate(as_completed(futures.keys())):
                file_path = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        security_findings[file_path] = findings

                    # Update progress
                    status_logger.update(i + 1, f"Found issues in {len(security_findings)} files")

                except Exception as e:
                    self.log_error(f"Error scanning {file_path}: {str(e)}")

        status_logger.complete(f"Scan complete. Found issues in {len(security_findings)} files")
        return security_findings

    def _scan_file(self, file_path: str, full_path: str) -> Optional[Dict[str, Any]]:
        """Scan a single file for security issues.

        Args:
            file_path: Relative path to the file
            full_path: Full path to the file

        Returns:
            Dictionary with security findings, or None if no issues found
        """
        try:
            # Read file content
            content = read_file(full_path)
            if not content:
                return None

            # Get file type
            file_type = get_file_type(full_path)

            # Scan for security issues
            raw_findings = scan_content_for_security_issues(content)

            # If no findings, return None
            if not raw_findings:
                return None

            # Process findings
            findings = {
                "pattern_findings": raw_findings,
                "file_type": file_type,
                "has_critical_methods": False  # Will be set in analysis phase
            }

            return findings

        except Exception as e:
            self.log_error(f"Error in scan_file for {file_path}: {str(e)}")
            return None

    def _analyze_security_findings(self, security_findings: Dict[str, Dict[str, Any]],
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and categorize security findings.

        Args:
            security_findings: Dictionary of security findings
            context: Context information

        Returns:
            Dictionary with analysis results
        """
        # Calculate vulnerability counts by category and severity
        vulnerability_counts = {
            "total": 0,
            "by_category": {},
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

        for file_path, findings in security_findings.items():
            pattern_findings = findings.get("pattern_findings", {})

            for category, category_findings in pattern_findings.items():
                # Update category counts
                if category not in vulnerability_counts["by_category"]:
                    vulnerability_counts["by_category"][category] = 0

                vulnerability_counts["by_category"][category] += len(category_findings)
                vulnerability_counts["total"] += len(category_findings)

                # Update severity counts
                for finding in category_findings:
                    severity = finding.get("severity", "low")
                    vulnerability_counts["by_severity"][severity] += 1

        # Analyze critical method coverage
        critical_methods = context.get("critical_methods", [])
        critical_method_files = set()

        for method in critical_methods:
            for location in method.get("locations", []):
                file_path = location.get("file", "")
                if file_path:
                    critical_method_files.add(file_path)

                    # Mark file as having critical methods
                    if file_path in security_findings:
                        security_findings[file_path]["has_critical_methods"] = True

        # Run deeper analysis on files with the most findings or critical methods
        detailed_analysis = self._run_detailed_analysis(security_findings, context)

        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(vulnerability_counts,
                                                         detailed_analysis,
                                                         context)

        # Generate remediation strategies
        remediation_strategies = self._generate_remediation_strategies(
            vulnerability_counts, detailed_analysis, context
        )

        return {
            "vulnerability_counts": vulnerability_counts,
            "critical_method_coverage": len(critical_method_files),
            "detailed_analysis": detailed_analysis,
            "risk_assessment": risk_assessment,
            "remediation_strategies": remediation_strategies
        }

    def _run_detailed_analysis(self, security_findings: Dict[str, Dict[str, Any]],
                               context: Dict[str, Any]) -> Dict[str, str]:
        """Run detailed analysis on high-priority files.

        Args:
            security_findings: Dictionary of security findings
            context: Context information

        Returns:
            Dictionary mapping file paths to detailed analysis
        """
        detailed_analysis = {}

        # Prioritize files for detailed analysis
        high_priority_files = []

        # Files with critical methods
        for file_path, findings in security_findings.items():
            if findings.get("has_critical_methods", False):
                high_priority_files.append((file_path, 3))  # Higher priority

        # Files with many findings
        for file_path, findings in security_findings.items():
            if file_path not in [f for f, _ in high_priority_files]:
                pattern_findings = findings.get("pattern_findings", {})
                finding_count = sum(len(category_findings) for category_findings in pattern_findings.values())

                if finding_count > 3:  # Threshold for "many" findings
                    high_priority_files.append((file_path, 2))
                elif finding_count > 0:
                    high_priority_files.append((file_path, 1))

        # Sort by priority
        high_priority_files.sort(key=lambda x: x[1], reverse=True)

        # Limit to 10 files for detailed analysis
        files_to_analyze = [file_path for file_path, _ in high_priority_files[:10]]

        # Run detailed analysis in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for file_path in files_to_analyze:
                future = executor.submit(
                    self._analyze_file_in_detail,
                    file_path,
                    security_findings[file_path],
                    context
                )
                futures[future] = file_path

            # Process results as they complete
            for future in as_completed(futures.keys()):
                file_path = futures[future]
                try:
                    analysis = future.result()
                    if analysis:
                        detailed_analysis[file_path] = analysis
                except Exception as e:
                    self.log_error(f"Error in detailed analysis for {file_path}: {str(e)}")

        return detailed_analysis

    def _analyze_file_in_detail(self, file_path: str,
                                findings: Dict[str, Any],
                                context: Dict[str, Any]) -> str:
        """Analyze a file in detail using LLM.

        Args:
            file_path: Path to the file
            findings: Security findings for the file
            context: Context information

        Returns:
            Detailed analysis text
        """
        # Create a prompt for detailed analysis
        prompt = f"""
        Perform a detailed security review of the following file, focusing on these categories:
        1. Input validation vulnerabilities
        2. Authentication and authorization issues
        3. Insecure handling of sensitive data
        4. Injection flaws (SQL, command, etc.)
        5. Cross-site scripting (XSS)
        6. Insecure configuration
        7. Insecure cryptography
        8. Insecure file operations
        9. Insecure deserialization
        10. Error handling issues
        11. Business logic vulnerabilities

        File: {file_path}
        File Type: {findings.get("file_type", "unknown")}
        Has Critical Methods: {findings.get("has_critical_methods", False)}

        Pattern-based findings already identified:
        {json.dumps(findings.get("pattern_findings", {}), indent=2)}

        For any identified vulnerabilities, provide:
        - Specific line numbers or areas of concern
        - Description of the issue
        - Potential impact
        - Recommendations for fixing

        Focus particularly on high-risk areas and provide a thorough analysis.
        """

        # Get analysis from LLM
        analysis_response = self.model.invoke([{"role": "system", "content": prompt}])

        return analysis_response.content

    def _generate_risk_assessment(self, vulnerability_counts: Dict[str, Any],
                                  detailed_analysis: Dict[str, str],
                                  context: Dict[str, Any]) -> str:
        """Generate a risk assessment for the security findings.

        Args:
            vulnerability_counts: Vulnerability count statistics
            detailed_analysis: Detailed analysis of high-priority files
            context: Context information

        Returns:
            Risk assessment text
        """
        # Create a prompt for risk assessment
        prompt = f"""
        Create a risk assessment matrix for the identified security issues.
        Include for each risk category:
        1. Risk description
        2. Likelihood (High/Medium/Low)
        3. Impact (High/Medium/Low)
        4. Overall risk rating
        5. Recommended mitigation priority

        Vulnerability Counts:
        Total Vulnerabilities: {vulnerability_counts.get("total", 0)}
        By Severity:
        - Critical: {vulnerability_counts.get("by_severity", {}).get("critical", 0)}
        - High: {vulnerability_counts.get("by_severity", {}).get("high", 0)}
        - Medium: {vulnerability_counts.get("by_severity", {}).get("medium", 0)}
        - Low: {vulnerability_counts.get("by_severity", {}).get("low", 0)}

        By Category:
        {json.dumps(vulnerability_counts.get("by_category", {}), indent=2)}

        Provide the assessment as a markdown table.
        """

        # Get assessment from LLM
        assessment_response = self.model.invoke([{"role": "system", "content": prompt}])

        return assessment_response.content

    def _generate_remediation_strategies(self, vulnerability_counts: Dict[str, Any],
                                         detailed_analysis: Dict[str, str],
                                         context: Dict[str, Any]) -> str:
        """Generate remediation strategies for the security findings.

        Args:
            vulnerability_counts: Vulnerability count statistics
            detailed_analysis: Detailed analysis of high-priority files
            context: Context information

        Returns:
            Remediation strategies text
        """
        # Create a prompt for remediation strategies
        prompt = f"""
        Based on all security findings, provide comprehensive remediation strategies.
        Include:
        1. Short-term fixes for critical/high-risk issues
        2. Long-term security improvements
        3. Secure coding practices specific to the identified technology stack
        4. Security tools and processes recommendations

        Vulnerability Counts:
        Total Vulnerabilities: {vulnerability_counts.get("total", 0)}
        By Severity:
        - Critical: {vulnerability_counts.get("by_severity", {}).get("critical", 0)}
        - High: {vulnerability_counts.get("by_severity", {}).get("high", 0)}
        - Medium: {vulnerability_counts.get("by_severity", {}).get("medium", 0)}
        - Low: {vulnerability_counts.get("by_severity", {}).get("low", 0)}

        By Category:
        {json.dumps(vulnerability_counts.get("by_category", {}), indent=2)}

        Provide detailed, actionable remediation guidance.
        """

        # Get strategies from LLM
        strategies_response = self.model.invoke([{"role": "system", "content": prompt}])

        return strategies_response.content

    def _generate_security_report(self, security_findings: Dict[str, Dict[str, Any]],
                                  analysis: Dict[str, Any],
                                  context: Dict[str, Any]) -> str:
        """Generate a comprehensive security report.

        Args:
            security_findings: Dictionary of security findings
            analysis: Analysis results
            context: Context information

        Returns:
            Formatted security report
        """
        report = "# Comprehensive Security Analysis Report\n\n"

        # Executive Summary
        report += "## Executive Summary\n\n"

        exec_summary_prompt = f"""
        Create a concise executive summary (3-5 paragraphs) of the security analysis findings, highlighting:
        1. Total vulnerabilities found by severity ({analysis["vulnerability_counts"]["total"]} total)
        2. Most critical security issues
        3. Overall security posture
        4. Top recommendations

        Vulnerability Counts:
        - Critical: {analysis["vulnerability_counts"]["by_severity"]["critical"]}
        - High: {analysis["vulnerability_counts"]["by_severity"]["high"]}
        - Medium: {analysis["vulnerability_counts"]["by_severity"]["medium"]}
        - Low: {analysis["vulnerability_counts"]["by_severity"]["low"]}
        """

        exec_summary_response = self.model.invoke([{"role": "system", "content": exec_summary_prompt}])
        report += f"{exec_summary_response.content}\n\n"

        # Vulnerability Summary
        report += "## Vulnerability Summary\n\n"

        # Vulnerability counts by severity
        report += "### Vulnerabilities by Severity\n\n"
        report += "| Severity | Count | Percentage |\n"
        report += "|----------|-------|------------|\n"

        total_vulns = analysis["vulnerability_counts"]["total"]
        for severity in ["critical", "high", "medium", "low"]:
            count = analysis["vulnerability_counts"]["by_severity"][severity]
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            report += f"| {severity.capitalize()} | {count} | {percentage:.1f}% |\n"

        report += f"| **Total** | {total_vulns} | 100% |\n\n"

        # Vulnerability counts by category
        report += "### Vulnerabilities by Category\n\n"
        report += "| Category | Count | Percentage |\n"
        report += "|----------|-------|------------|\n"

        by_category = analysis["vulnerability_counts"]["by_category"]
        for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            report += f"| {category} | {count} | {percentage:.1f}% |\n"

        report += "\n"

        # Risk Assessment
        report += "## Risk Assessment\n\n"
        report += f"{analysis['risk_assessment']}\n\n"

        # Detailed Findings
        report += "## Detailed Security Findings\n\n"

        # Files with critical methods
        critical_files = [file_path for file_path, findings in security_findings.items()
                          if findings.get("has_critical_methods", False)]

        if critical_files:
            report += "### Files with Critical Methods\n\n"

            for file_path in critical_files:
                findings = security_findings.get(file_path, {})
                report += f"#### {file_path}\n\n"

                # Add detailed analysis if available
                if file_path in analysis.get("detailed_analysis", {}):
                    report += f"{analysis['detailed_analysis'][file_path]}\n\n"
                else:
                    # Show pattern-based findings
                    report += "Pattern-based findings:\n\n"
                    pattern_findings = findings.get("pattern_findings", {})

                    for category, category_findings in pattern_findings.items():
                        report += f"**{category}**:\n\n"

                        for finding in category_findings:
                            severity = finding.get("severity", "low")
                            pattern = finding.get("pattern", "Unknown pattern")
                            lines = finding.get("line_numbers", [])

                            report += f"- **{severity.upper()}**: {pattern}\n"
                            if lines:
                                report += f"  - Lines: {', '.join(map(str, lines))}\n"

                        report += "\n"

        # Other files with vulnerabilities
        other_files = [file_path for file_path, findings in security_findings.items()
                       if not findings.get("has_critical_methods", False)]

        if other_files:
            report += "### Other Files with Security Issues\n\n"

            # Sort by number of findings
            def count_findings(file_path):
                findings = security_findings.get(file_path, {})
                pattern_findings = findings.get("pattern_findings", {})
                return sum(len(category_findings) for category_findings in pattern_findings.values())

            other_files.sort(key=count_findings, reverse=True)

            # Show detailed analysis for top files
            for file_path in other_files[:10]:  # Limit to top 10
                findings = security_findings.get(file_path, {})
                report += f"#### {file_path}\n\n"

                # Add detailed analysis if available
                if file_path in analysis.get("detailed_analysis", {}):
                    report += f"{analysis['detailed_analysis'][file_path]}\n\n"
                else:
                    # Show pattern-based findings
                    report += "Pattern-based findings:\n\n"
                    pattern_findings = findings.get("pattern_findings", {})

                    for category, category_findings in pattern_findings.items():
                        report += f"**{category}**:\n\n"

                        for finding in category_findings:
                            severity = finding.get("severity", "low")
                            pattern = finding.get("pattern", "Unknown pattern")
                            lines = finding.get("line_numbers", [])

                            report += f"- **{severity.upper()}**: {pattern}\n"
                            if lines:
                                report += f"  - Lines: {', '.join(map(str, lines))}\n"

                        report += "\n"

        # Remediation Strategies
        report += "## Remediation Strategies\n\n"
        report += f"{analysis['remediation_strategies']}\n\n"

        # Security Best Practices
        report += "## Security Best Practices\n\n"

        best_practices_prompt = f"""
        Based on the technology stack and vulnerabilities identified, provide tailored security best practices for this codebase.
        Include practices related to:
        1. Secure coding standards
        2. Security testing and review processes
        3. Authentication and authorization
        4. Data handling and storage
        5. API security
        6. Error handling and logging

        Format as actionable recommendations.
        """

        best_practices_response = self.model.invoke([{"role": "system", "content": best_practices_prompt}])
        report += f"{best_practices_response.content}\n\n"

        # Next Steps
        report += "## Next Steps and Implementation Plan\n\n"

        next_steps_prompt = f"""
        Create a prioritized implementation plan for addressing the security issues identified.
        Include:
        1. Immediate actions (within 1 week)
        2. Short-term improvements (within 1 month)
        3. Long-term security enhancements (within 3-6 months)
        4. Metrics to track security improvements

        Make the plan specific and actionable.
        """

        next_steps_response = self.model.invoke([{"role": "system", "content": next_steps_prompt}])
        report += f"{next_steps_response.content}\n\n"

        # Conclusion
        report += "## Conclusion\n\n"

        conclusion_prompt = "Write a brief conclusion summarizing the security analysis and the path forward."
        conclusion_response = self.model.invoke([{"role": "system", "content": conclusion_prompt}])
        report += f"{conclusion_response.content}\n\n"

        return report