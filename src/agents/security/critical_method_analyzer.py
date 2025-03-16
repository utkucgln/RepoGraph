"""
Critical method analyzer agent.

This module provides an agent that identifies and analyzes security-critical
methods and functions in the codebase.
"""

import os
import re
import logging
import json
from typing import Dict, Any, List, Optional, Tuple, Set

from src.core.agent_base import Agent
from src.utils.file_utils import read_file, get_file_type
from src.utils.security_patterns import SECURITY_PATTERNS, scan_content_for_security_issues
from src.utils.logging_utils import log_execution_time


class CriticalMethodAnalyzerAgent(Agent):
    """Agent for analyzing security-critical methods.

    This agent identifies methods that handle sensitive operations
    such as authentication, authorization, and data validation.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the critical method analyzer agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and analyze critical methods.

        Args:
            state: Current state containing file descriptions

        Returns:
            Updated state with critical method analysis
        """
        self.log_info("Critical Method Analyzer: Starting analysis")

        # Get file list and repository path
        file_list = self._get_file_list(state)
        repo_path = self._extract_repo_path(state)

        if not file_list:
            self.log_error("Critical Method Analyzer: No file list found in state")
            error_msg = "No file list found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        if not repo_path:
            self.log_error("Critical Method Analyzer: No repository path found in state")
            error_msg = "No repository path found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Extract method definitions from files
        method_definitions, method_calls = self._extract_method_definitions(file_list, repo_path)
        self.log_info(f"Extracted {len(method_definitions)} method definitions")

        # Get file descriptions if available
        file_descriptions = self._get_file_descriptions(state)

        # Identify security-critical methods
        critical_methods = self._identify_critical_methods(method_definitions, method_calls, file_descriptions)
        self.log_info(f"Identified {len(critical_methods)} critical methods")

        # Analyze critical methods and their data flow
        analysis = self._analyze_critical_methods(critical_methods, method_definitions, method_calls, repo_path)

        # Generate the critical method report
        report = self._generate_report(critical_methods, analysis)

        # Add report to state
        state = self.add_message_to_state(
            state,
            report,
            "system",
            "critical_method_report"
        )

        # Save report to file if output directory exists
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_path = os.path.join(output_dir, "critical_method_analysis.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        self.log_info(f"Report saved to {report_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Critical Method Analyzer: Analysis complete")
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

    def _get_file_descriptions(self, state: Dict[str, Any]) -> Optional[str]:
        """Get file descriptions from state.

        Args:
            state: Current state

        Returns:
            File descriptions if found, None otherwise
        """
        # Try to get from file_descriptions message
        file_descriptions_message = self.get_last_message_by_name(state, "file_descriptions")
        if file_descriptions_message:
            content = file_descriptions_message.get("content", "")
            if content and "File Descriptions:" in content:
                return content.split("File Descriptions:")[1].strip()
            return content

        return None

    def _extract_method_definitions(self, file_list: List[str],
                                    repo_path: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, List[str]]]:
        """Extract method definitions from files.

        Args:
            file_list: List of file paths
            repo_path: Repository path

        Returns:
            Tuple of (method_definitions, method_calls)
        """
        method_definitions = {}  # method_name -> list of definitions
        method_calls = {}  # method_name -> list of files where called

        for file_path in file_list:
            try:
                file_ext = os.path.splitext(file_path)[1].lower()

                # Skip non-code files
                if file_ext not in ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.rb', '.php', '.go', '.cs']:
                    continue

                # Read file content
                full_path = os.path.join(repo_path, file_path)
                file_content = read_file(full_path)
                if not file_content:
                    continue

                # Extract method definitions based on language
                if file_ext == '.py':
                    self._extract_python_methods(file_path, file_content, method_definitions)
                elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
                    self._extract_js_methods(file_path, file_content, method_definitions)
                elif file_ext == '.java':
                    self._extract_java_methods(file_path, file_content, method_definitions)
                # Add more language extractors as needed

                # Extract method calls for all methods we've found so far
                for method_name in method_definitions:
                    self._extract_method_calls(method_name, file_path, file_content, method_calls)

            except Exception as e:
                self.log_error(f"Error processing {file_path}: {str(e)}")

        return method_definitions, method_calls

    def _extract_python_methods(self, file_path: str, content: str,
                                method_definitions: Dict[str, List[Dict[str, Any]]]) -> None:
        """Extract method definitions from Python files.

        Args:
            file_path: Path to the file
            content: File content
            method_definitions: Dictionary to update with method definitions
        """
        # Match function definitions
        method_pattern = r'def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\):'
        matches = re.finditer(method_pattern, content)

        for match in matches:
            method_name = match.group(1)
            parameters = match.group(2)

            # Extract method body (simplified approach)
            start_pos = match.end()
            lines = content[start_pos:].split('\n')
            body_lines = []
            indent_level = None

            for line in lines:
                if line.strip() == "":
                    if body_lines:  # Only add empty lines after we've started the body
                        body_lines.append(line)
                    continue

                # Determine indent level from first non-empty line if not set
                if indent_level is None:
                    indent_match = re.match(r'^(\s+)', line)
                    if indent_match:
                        indent_level = len(indent_match.group(1))
                    else:
                        break  # No indentation means end of method

                # Check if this line has less indentation than the method body
                current_indent = 0
                indent_match = re.match(r'^(\s+)', line)
                if indent_match:
                    current_indent = len(indent_match.group(1))

                if indent_level is not None and current_indent < indent_level:
                    break  # End of method body

                body_lines.append(line)

                # Break if we've collected enough of the method body (prevent huge methods)
                if len(body_lines) > 50:
                    body_lines.append("... (method body truncated)")
                    break

            method_body = '\n'.join(body_lines)

            # Get line number
            line_no = content[:match.start()].count('\n') + 1

            # Add to method definitions
            if method_name not in method_definitions:
                method_definitions[method_name] = []

            method_definitions[method_name].append({
                "file": file_path,
                "line": line_no,
                "parameters": parameters,
                "body": method_body,
                "full_signature": f"def {method_name}({parameters}):"
            })

    def _extract_js_methods(self, file_path: str, content: str,
                            method_definitions: Dict[str, List[Dict[str, Any]]]) -> None:
        """Extract method definitions from JavaScript/TypeScript files.

        Args:
            file_path: Path to the file
            content: File content
            method_definitions: Dictionary to update with method definitions
        """
        # Match function declarations (function keyword)
        func_pattern = r'function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)'
        matches = re.finditer(func_pattern, content)

        for match in matches:
            method_name = match.group(1)
            parameters = match.group(2)

            # Extract method body
            start_pos = content.find('{', match.end())
            if start_pos == -1:
                continue

            # Find matching closing brace (simplified approach)
            open_braces = 1
            pos = start_pos + 1
            body_end = None

            while pos < len(content) and open_braces > 0:
                if content[pos] == '{':
                    open_braces += 1
                elif content[pos] == '}':
                    open_braces -= 1
                    if open_braces == 0:
                        body_end = pos
                        break
                pos += 1

            if body_end is None:
                continue

            method_body = content[start_pos:body_end + 1]
            if len(method_body) > 1000:
                method_body = method_body[:1000] + "\n... (method body truncated)"

            # Get line number
            line_no = content[:match.start()].count('\n') + 1

            # Add to method definitions
            if method_name not in method_definitions:
                method_definitions[method_name] = []

            method_definitions[method_name].append({
                "file": file_path,
                "line": line_no,
                "parameters": parameters,
                "body": method_body,
                "full_signature": f"function {method_name}({parameters})"
            })

        # Match class/object method declarations
        method_pattern = r'(?:async\s+)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*{'
        matches = re.finditer(method_pattern, content)

        for match in matches:
            # Skip if this doesn't look like a method (might be an if statement, etc.)
            pre_char_pos = match.start(1) - 1
            if pre_char_pos >= 0 and content[pre_char_pos] not in ['\n', '\r', '\t', ' ', '{', ',', ':']:
                continue

            method_name = match.group(1)
            parameters = match.group(2)

            # Skip common JavaScript keywords that might match the pattern
            if method_name in ['if', 'while', 'for', 'switch', 'catch']:
                continue

            # Extract method body (simplified)
            start_pos = content.find('{', match.end())
            if start_pos == -1:
                continue

            # Find matching closing brace
            open_braces = 1
            pos = start_pos + 1
            body_end = None

            while pos < len(content) and open_braces > 0:
                if content[pos] == '{':
                    open_braces += 1
                elif content[pos] == '}':
                    open_braces -= 1
                    if open_braces == 0:
                        body_end = pos
                        break
                pos += 1

            if body_end is None:
                continue

            method_body = content[start_pos:body_end + 1]
            if len(method_body) > 1000:
                method_body = method_body[:1000] + "\n... (method body truncated)"

            # Get line number
            line_no = content[:match.start()].count('\n') + 1

            # Add to method definitions
            if method_name not in method_definitions:
                method_definitions[method_name] = []

            method_definitions[method_name].append({
                "file": file_path,
                "line": line_no,
                "parameters": parameters,
                "body": method_body,
                "full_signature": f"{method_name}({parameters})"
            })

    def _extract_java_methods(self, file_path: str, content: str,
                              method_definitions: Dict[str, List[Dict[str, Any]]]) -> None:
        """Extract method definitions from Java files.

        Args:
            file_path: Path to the file
            content: File content
            method_definitions: Dictionary to update with method definitions
        """
        # Match method declarations
        method_pattern = r'(?:public|protected|private|static|\s)+[\w\<\>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w\s,]+)?\s*\{'
        matches = re.finditer(method_pattern, content)

        for match in matches:
            method_name = match.group(1)
            parameters = match.group(2)

            # Extract method body
            start_pos = content.find('{', match.end())
            if start_pos == -1:
                continue

            # Find matching closing brace
            open_braces = 1
            pos = start_pos + 1
            body_end = None

            while pos < len(content) and open_braces > 0:
                if content[pos] == '{':
                    open_braces += 1
                elif content[pos] == '}':
                    open_braces -= 1
                    if open_braces == 0:
                        body_end = pos
                        break
                pos += 1

            if body_end is None:
                continue

            method_body = content[start_pos:body_end + 1]
            if len(method_body) > 1000:
                method_body = method_body[:1000] + "\n... (method body truncated)"

            # Get line number
            line_no = content[:match.start()].count('\n') + 1

            # Add to method definitions
            if method_name not in method_definitions:
                method_definitions[method_name] = []

            method_definitions[method_name].append({
                "file": file_path,
                "line": line_no,
                "parameters": parameters,
                "body": method_body,
                "full_signature": f"{method_name}({parameters})"
            })

    def _extract_method_calls(self, method_name: str, file_path: str,
                              content: str, method_calls: Dict[str, List[str]]) -> None:
        """Extract method calls for a specific method.

        Args:
            method_name: Method name to search for
            file_path: Path to the file
            content: File content
            method_calls: Dictionary to update with method calls
        """
        # Simple pattern to find method calls
        call_pattern = rf'[^a-zA-Z0-9_]{re.escape(method_name)}\s*\('

        if re.search(call_pattern, content):
            if method_name not in method_calls:
                method_calls[method_name] = []

            if file_path not in method_calls[method_name]:
                method_calls[method_name].append(file_path)

    def _identify_critical_methods(self, method_definitions: Dict[str, List[Dict[str, Any]]],
                                   method_calls: Dict[str, List[str]],
                                   file_descriptions: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Identify security-critical methods based on patterns and content.

        Args:
            method_definitions: Dictionary of method definitions
            method_calls: Dictionary of method calls
            file_descriptions: Optional file descriptions for context

        Returns:
            Dictionary of critical methods with analysis information
        """
        critical_methods = {}

        # Process each method for security patterns
        for method_name, definitions in method_definitions.items():
            for definition in definitions:
                method_body = definition.get("body", "")

                # Skip methods with no body
                if not method_body:
                    continue

                # Check for security-related patterns in method name and body
                matched_categories = self._check_security_patterns(method_name, method_body)

                if matched_categories:
                    # Method matches security patterns, mark as critical
                    if method_name not in critical_methods:
                        critical_methods[method_name] = {
                            "security_categories": matched_categories,
                            "definitions": [definition],
                            "called_in": method_calls.get(method_name, [])
                        }
                    else:
                        critical_methods[method_name]["definitions"].append(definition)
                        # Update security categories
                        for category in matched_categories:
                            if category not in critical_methods[method_name]["security_categories"]:
                                critical_methods[method_name]["security_categories"].append(category)

        # If few critical methods were found, use LLM to identify more based on context
        if len(critical_methods) < 5 and file_descriptions:
            llm_critical_methods = self._identify_critical_methods_with_llm(
                method_definitions, method_calls, file_descriptions, critical_methods
            )

            # Merge LLM-identified methods
            for method_name, info in llm_critical_methods.items():
                if method_name not in critical_methods:
                    critical_methods[method_name] = info
                else:
                    # Merge categories
                    for category in info.get("security_categories", []):
                        if category not in critical_methods[method_name]["security_categories"]:
                            critical_methods[method_name]["security_categories"].append(category)

                    # Merge other attributes if needed
                    if "why_critical" in info and "why_critical" not in critical_methods[method_name]:
                        critical_methods[method_name]["why_critical"] = info["why_critical"]
                    if "potential_vulnerabilities" in info and "potential_vulnerabilities" not in critical_methods[
                        method_name]:
                        critical_methods[method_name]["potential_vulnerabilities"] = info["potential_vulnerabilities"]

        return critical_methods

    def _check_security_patterns(self, method_name: str, method_body: str) -> List[str]:
        """Check if a method matches security-related patterns.

        Args:
            method_name: Name of the method
            method_body: Method body content

        Returns:
            List of matched security categories
        """
        matched_categories = []

        # Check method name against security patterns
        for category, info in SECURITY_PATTERNS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, method_name, re.IGNORECASE):
                    matched_categories.append(category)
                    break

            # Also check method body if not already matched
            if category not in matched_categories:
                for pattern in info["patterns"]:
                    if re.search(pattern, method_body):
                        matched_categories.append(category)
                        break

        return matched_categories

    def _identify_critical_methods_with_llm(self, method_definitions: Dict[str, List[Dict[str, Any]]],
                                            method_calls: Dict[str, List[str]],
                                            file_descriptions: str,
                                            existing_methods: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Use LLM to identify critical methods based on context.

        Args:
            method_definitions: Dictionary of method definitions
            method_calls: Dictionary of method calls
            file_descriptions: File descriptions for context
            existing_methods: Already identified critical methods

        Returns:
            Dictionary of additional critical methods
        """
        # Create a prompt for the LLM
        prompt = f"""
        Based on the file descriptions and method definitions provided, identify security-critical methods 
        that handle sensitive operations such as authentication, authorization, data validation, input sanitization,
        encryption, sensitive data handling, or other security-related functionality.

        For each critical method you identify, provide:
        1. Method name
        2. Security category (Authentication, Authorization, InputValidation, etc.)
        3. Why this method is critical from a security perspective
        4. Potential security vulnerabilities to look for in this method
        5. Recommended security improvements

        File Descriptions:
        {file_descriptions[:5000]}  # Limit to first 5000 characters

        I've already identified the following critical methods (don't include these in your response):
        {", ".join(existing_methods.keys())}

        Here are some examples of methods in the codebase:
        """

        # Add a sample of method definitions to the prompt
        sample_size = min(20, len(method_definitions))
        sample_methods = list(method_definitions.keys())[:sample_size]

        for method_name in sample_methods:
            definition = method_definitions[method_name][0]  # Get the first definition
            prompt += f"\nMethod: {method_name}\nFile: {definition['file']}\nSignature: {definition['full_signature']}\n"

            # Add a snippet of the method body
            body_lines = definition.get("body", "").split("\n")[:5]
            if body_lines:
                prompt += "Body snippet:\n"
                for line in body_lines:
                    prompt += f"{line}\n"
                if len(definition.get("body", "").split("\n")) > 5:
                    prompt += "...\n"

        prompt += """
        Output the critical methods you identify in JSON format, like this:
        {
          "method_name1": {
            "security_categories": ["Authentication", "InputValidation"],
            "why_critical": "This method validates user credentials and generates authentication tokens.",
            "potential_vulnerabilities": "Could be vulnerable to brute force attacks if rate limiting is not implemented.",
            "recommended_improvements": "Add rate limiting and account lockout mechanisms."
          },
          "method_name2": {
            "security_categories": ["DataStorage"],
            "why_critical": "This method stores sensitive user data in the database.",
            "potential_vulnerabilities": "Data might not be properly encrypted before storage.",
            "recommended_improvements": "Ensure all sensitive data is encrypted using strong encryption."
          }
        }

        Provide only the JSON object, no other text.
        """

        # Get response from LLM
        self.log_info("Invoking LLM for critical method identification")
        response = self.model.invoke([{"role": "system", "content": prompt}])

        # Extract JSON from response
        try:
            # Try to find JSON in response
            json_pattern = r'```(?:json)?\n(.*?)\n```'
            match = re.search(json_pattern, response.content, re.DOTALL)

            if match:
                json_str = match.group(1)
                critical_methods = json.loads(json_str)
            else:
                # If no code block, try to parse the whole response
                critical_methods = json.loads(response.content)

            # Validate and process the results
            result = {}
            for method_name, info in critical_methods.items():
                # Skip if method doesn't exist in the codebase
                if method_name not in method_definitions:
                    continue

                # Add definitions and call information
                info["definitions"] = method_definitions[method_name]
                info["called_in"] = method_calls.get(method_name, [])
                result[method_name] = info

            return result

        except Exception as e:
            self.log_error(f"Error parsing LLM response for critical methods: {str(e)}")
            return {}

    def _analyze_critical_methods(self, critical_methods: Dict[str, Dict[str, Any]],
                                  method_definitions: Dict[str, List[Dict[str, Any]]],
                                  method_calls: Dict[str, List[str]],
                                  repo_path: str) -> Dict[str, Any]:
        """Analyze critical methods and their data flow.

        Args:
            critical_methods: Dictionary of critical methods
            method_definitions: Dictionary of all method definitions
            method_calls: Dictionary of method calls
            repo_path: Repository path

        Returns:
            Dictionary with analysis results
        """
        if not critical_methods:
            return {
                "data_flow_analysis": "No critical methods identified for data flow analysis.",
                "security_recommendations": "No security recommendations due to lack of critical methods."
            }

        # Collect information for data flow analysis
        data_flow_prompt = f"""
        Analyze the data flow between these security-critical methods in this application. Focus on:
        1. How data moves between security-critical methods
        2. Potential vulnerabilities in the data flow
        3. Sanitization and validation points
        4. Security boundaries crossed

        Critical Methods:
        """

        # Add critical method information to the prompt
        for method_name, info in critical_methods.items():
            categories = ", ".join(info.get("security_categories", ["Unknown"]))
            data_flow_prompt += f"\n{method_name} - Categories: {categories}\n"

            # Add definition information
            for definition in info.get("definitions", []):
                data_flow_prompt += f"  - File: {definition.get('file', 'Unknown')}, Line: {definition.get('line', 'Unknown')}\n"

                # Add a snippet of the method body
                body_lines = definition.get("body", "").split("\n")[:3]
                if body_lines:
                    data_flow_prompt += "    Body snippet:\n"
                    for line in body_lines:
                        data_flow_prompt += f"    {line}\n"
                    if len(definition.get("body", "").split("\n")) > 3:
                        data_flow_prompt += "    ...\n"

            # Add call sites
            call_sites = info.get("called_in", [])
            if call_sites:
                data_flow_prompt += f"  - Called in: {', '.join(call_sites[:5])}"
                if len(call_sites) > 5:
                    data_flow_prompt += f" and {len(call_sites) - 5} more files"
                data_flow_prompt += "\n"

        # Invoke LLM for data flow analysis
        self.log_info("Invoking LLM for data flow analysis")
        data_flow_response = self.model.invoke([{"role": "system", "content": data_flow_prompt}])
        data_flow_analysis = data_flow_response.content

        # Generate security recommendations
        recommendations_prompt = f"""
        Based on the critical methods identified and the data flow analysis, provide detailed security recommendations for:
        1. Improving each critical method's security
        2. Enhancing data flow security between methods
        3. Additional security controls needed
        4. Testing strategies for these critical methods

        Critical Methods:
        {json.dumps(critical_methods, indent=2)}

        Data Flow Analysis:
        {data_flow_analysis}

        Provide specific, actionable security recommendations.
        """

        self.log_info("Invoking LLM for security recommendations")
        recommendations_response = self.model.invoke([{"role": "system", "content": recommendations_prompt}])
        security_recommendations = recommendations_response.content

        return {
            "data_flow_analysis": data_flow_analysis,
            "security_recommendations": security_recommendations
        }

    def _generate_report(self, critical_methods: Dict[str, Dict[str, Any]],
                         analysis: Dict[str, Any]) -> str:
        """Generate a comprehensive report on critical methods.

        Args:
            critical_methods: Dictionary of critical methods
            analysis: Analysis results

        Returns:
            Formatted report content
        """
        report = "# Critical Method Analysis Report\n\n"

        # Overview Section
        report += "## Overview\n\n"
        report += (
            "This report provides an analysis of security-critical methods identified in the codebase. "
            "It includes a summary of critical methods, data flow analysis, and security recommendations based on the analysis.\n\n"
        )

        # Critical Methods Section
        report += "## Critical Methods Identified\n\n"
        if not critical_methods:
            report += "No security-critical methods were identified in the analysis.\n\n"
        else:
            for method_name, info in critical_methods.items():
                report += f"### Method: `{method_name}`\n"
                # Security Categories
                categories = info.get("security_categories", [])
                if categories:
                    report += f"- **Security Categories:** {', '.join(categories)}\n"
                # Definitions
                definitions = info.get("definitions", [])
                if definitions:
                    report += "- **Definitions:**\n"
                    for definition in definitions:
                        file_path = definition.get("file", "Unknown")
                        line_no = definition.get("line", "Unknown")
                        signature = definition.get("full_signature", "")
                        report += f"  - Found in `{file_path}` at line {line_no}\n"
                        report += f"    - **Signature:** `{signature}`\n"
                        # Provide a snippet of the method body
                        body_lines = definition.get("body", "").split("\n")
                        snippet = "\n".join(body_lines[:5])
                        report += "    - **Body Snippet:**\n"
                        report += "    ```\n"
                        report += f"{snippet}\n"
                        report += "    ```\n"
                # Called In Information
                called_in = info.get("called_in", [])
                if called_in:
                    report += f"- **Called In:** {', '.join(called_in)}\n"
                report += "\n"

        # Data Flow Analysis Section
        report += "## Data Flow Analysis\n\n"
        data_flow = analysis.get("data_flow_analysis", "No data flow analysis available.")
        report += f"{data_flow}\n\n"

        # Security Recommendations Section
        report += "## Security Recommendations\n\n"
        recommendations = analysis.get("security_recommendations", "No security recommendations available.")
        report += f"{recommendations}\n\n"

        return report
