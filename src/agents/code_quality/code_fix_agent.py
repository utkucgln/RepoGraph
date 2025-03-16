"""
Enhanced Code fix agent.

This module provides an agent that analyzes error logs and provides
fixes for code-related issues using LLM for most of the analysis.
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

from src.core.agent_base import Agent
from src.utils.file_utils import read_file
from src.utils.logging_utils import log_execution_time


class CodeFixAgent(Agent):
    """Agent for analyzing logs and providing code fixes using LLM extensively.

    This agent examines error logs, repository code, and user query to identify
    issues and suggest fixes, leveraging LLM capabilities for most of the analysis.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the enhanced code fix agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and provide code fixes.

        Args:
            state: Current state containing repository information and error logs

        Returns:
            Updated state with code fix recommendations
        """
        self.log_info("Enhanced Code Fix Agent: Starting analysis")

        # Extract user query, log details, and repository path
        user_query, logs, repo_path = self._extract_query_logs_and_path(state)

        if not logs:
            self.log_error("Enhanced Code Fix Agent: No logs found in user query")
            error_msg = "No logs found. Please include logs after 'Logs:' keyword."
            return self.add_message_to_state(state, error_msg, "system", "error")

        if not repo_path:
            self.log_error("Enhanced Code Fix Agent: No repository path found")
            error_msg = "No repository path found. Please specify with 'Path:' keyword."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Use LLM to identify potentially relevant files from logs
        relevant_files = self._identify_relevant_files(logs, user_query)
        self.log_info(f"Identified {len(relevant_files)} potentially relevant files")

        # Read content of relevant files
        file_contents = self._read_relevant_files(relevant_files, repo_path)

        # Use LLM to identify additional files that might be related
        additional_files = self._identify_additional_relevant_files(logs, user_query, file_contents, repo_path)

        # Read additional files
        additional_file_contents = self._read_relevant_files(additional_files, repo_path)
        file_contents.update(additional_file_contents)

        self.log_info(f"Total files being analyzed: {len(file_contents)}")

        # Generate code fixes using LLM
        fixes = self._generate_code_fixes_with_llm(logs, user_query, file_contents)

        # Generate the code fix report
        report = self._generate_code_fix_report(logs, user_query, fixes, file_contents)

        # Add report to state
        state = self.add_message_to_state(
            state,
            report,
            "system",
            "code_fixes"
        )

        # Save report to file if output directory exists
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_path = os.path.join(output_dir, "code_fixes.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        self.log_info(f"Report saved to {report_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Enhanced Code Fix Agent: Analysis complete")
        return state

    def _extract_query_logs_and_path(self, state: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract user query, logs and repository path from state.

        Args:
            state: Current state

        Returns:
            Tuple of (user_query, logs, repo_path)
        """
        logs = None
        repo_path = None
        user_query = None

        # Extract user query, logs and repository path from user query
        for message in state.get("messages", []):
            if isinstance(message, dict) and message.get("role") == "user":
                user_query = message.get("content", "")
            elif hasattr(message, "type") and message.type == "human":
                user_query = getattr(message, "content", "")
            else:
                continue

            # Extract repository path
            repo_path_match = re.search(r'Path:\s*([^\n]+)', user_query)
            if repo_path_match:
                repo_path = repo_path_match.group(1).strip()

            # Extract logs
            if "Logs:" in user_query:
                logs = user_query.split("Logs:", 1)[1].strip()
                # Remove logs part from user query for separate analysis
                user_query = user_query.split("Logs:", 1)[0].strip()
                break

        # If repo_path not found in user query, check state
        if not repo_path:
            repo_path = state.get("repo_path")

            # If still not found, check messages for a path specification
            if not repo_path:
                for message in state.get("messages", []):
                    if isinstance(message, dict):
                        content = message.get("content", "")
                    else:
                        content = getattr(message, "content", "")

                    if "Path:" in content:
                        parts = content.split("Path:")
                        if len(parts) > 1:
                            repo_path = parts[1].strip()
                            if "\n" in repo_path:
                                repo_path = repo_path.split("\n")[0].strip()
                            break

        return user_query, logs, repo_path

    def _identify_relevant_files(self, logs: str, user_query: str) -> List[str]:
        """Use LLM to identify potentially relevant files from logs and user query.

        Args:
            logs: Log content
            user_query: User's original query

        Returns:
            List of potentially relevant file paths
        """
        prompt = f"""
        You are an expert at debugging code issues. Based on the error logs and user query provided,
        identify all file paths that might be relevant to the issue. Include both files directly 
        mentioned in the logs and those that might be related based on your understanding of 
        software architecture.

        User Query:
        {user_query}

        Error Logs:
        {logs}

        Extract and list ALL possible file paths mentioned or implied in the logs, including:
        1. Files directly mentioned in error traces
        2. Files that might contain the functions or classes mentioned in errors
        3. Configuration files that might be related to the error
        4. Files that typically interact with the mentioned files in a typical software architecture

        Format your response as a simple list of file paths, one per line, without any additional commentary.
        """

        response = self.model.invoke([{"role": "system", "content": prompt}])
        file_paths = [line.strip() for line in response.content.splitlines() if line.strip()]

        # Clean up file paths to remove any non-path content
        cleaned_paths = []
        for path in file_paths:
            # Remove common prefixes from LLM responses
            path = re.sub(r'^[\d\.\-\* ]*', '', path)

            # Remove trailing commentary
            path = re.sub(r' .*$', '', path)

            # Only add if it has common file extensions or looks like a path
            if '.' in path or '/' in path:
                cleaned_paths.append(path)

        return cleaned_paths

    def _read_relevant_files(self, file_paths: List[str], repo_path: str) -> Dict[str, str]:
        """Read content of files mentioned in error logs.

        Args:
            file_paths: List of file paths from logs
            repo_path: Repository path

        Returns:
            Dictionary mapping file paths to their content
        """
        file_contents = {}

        for file_path in file_paths:
            try:
                # Clean file path
                file_path = file_path.strip()

                # Skip if file path is empty
                if not file_path:
                    continue

                # Extract file name as last word in the path
                file_name = os.path.basename(file_path)

                # First try the exact path
                full_path = os.path.join(repo_path, file_path)
                if os.path.exists(full_path) and os.path.isfile(full_path):
                    content = read_file(full_path)
                    if content:
                        file_contents[file_path] = content
                    continue

                # If not found, search for the file name in the repo
                for root, dirs, files in os.walk(repo_path):
                    if file_name in files:
                        found_path = os.path.join(root, file_name)
                        rel_path = os.path.relpath(found_path, repo_path)
                        content = read_file(found_path)
                        if content:
                            file_contents[rel_path] = content
                        break

            except Exception as e:
                self.log_error(f"Error reading file {file_path}: {str(e)}")

        return file_contents

    def _identify_additional_relevant_files(self, logs: str, user_query: str,
                                          file_contents: Dict[str, str], repo_path: str) -> List[str]:
        """Use LLM to identify additional files that might be related based on available file contents.

        Args:
            logs: Log content
            user_query: User's original query
            file_contents: Already identified file contents
            repo_path: Repository path

        Returns:
            List of additional file paths that might be relevant
        """
        if not file_contents:
            return []

        # Create a prompt with available files to help LLM identify additional files
        file_snippets = {}
        for file_path, content in file_contents.items():
            # Trim long files to first 50 lines and last 20 lines
            lines = content.splitlines()
            if len(lines) > 70:
                content = "\n".join(lines[:50] + ["..."] + lines[-20:])
            file_snippets[file_path] = content

        prompt = f"""
        Based on the error logs, user query, and the content of the files I've found so far,
        identify additional files that might be relevant to resolving the issue.

        User Query:
        {user_query}

        Error Logs:
        {logs}
        
        Files already found:
        {", ".join(file_contents.keys())}
        
        Here are snippets from these files:
        """

        for file_path, snippet in file_snippets.items():
            prompt += f"\n--- {file_path} ---\n{snippet}\n\n"

        prompt += """
        Based on these file contents and the error, suggest additional files that might be relevant.
        Look for:
        1. Imported modules and their potential file paths
        2. Related classes or functions that might be in separate files
        3. Configuration files referenced in the code
        4. Database models or schema files that might be related
        5. Any other files that would help understand and fix the issue
        
        Format your response as a simple list of likely file paths, one per line. Only include files that
        you believe have a high probability of existing and being relevant.
        """

        response = self.model.invoke([{"role": "system", "content": prompt}])
        additional_files = [line.strip() for line in response.content.splitlines() if line.strip()]

        # Clean up file paths
        cleaned_paths = []
        for path in additional_files:
            # Remove common prefixes from LLM responses
            path = re.sub(r'^[\d\.\-\* ]*', '', path)

            # Remove trailing commentary
            path = re.sub(r' .*$', '', path)

            # Only add if it looks like a path and isn't already in file_contents
            if ('.' in path or '/' in path) and path not in file_contents:
                cleaned_paths.append(path)

        return cleaned_paths

    def _generate_code_fixes_with_llm(self, logs: str, user_query: str,
                                    file_contents: Dict[str, str]) -> str:
        """Generate fixes for code issues based on logs, user query and file content using LLM.

        Args:
            logs: Log content
            user_query: User's original query
            file_contents: Dictionary of file contents

        Returns:
            Code fixes recommendations
        """
        # Create prompt for code fixes
        prompt = f"""
        You are an expert code debugger and problem solver. Based on the user query, log details, 
        and code files provided, identify the root cause of the issues and provide detailed fixes.

        User Query:
        {user_query}

        Log Details:
        {logs}

        Relevant Files:
        """

        # Add file contents to prompt
        for file_path, content in file_contents.items():
            # Trim long files to make sure we don't exceed context limits
            lines = content.splitlines()
            if len(lines) > 200:  # Arbitrary limit, adjust based on model's context size
                content = "\n".join(lines[:100] + ["..."] + lines[-100:])

            prompt += f"\n--- {file_path} ---\n{content}\n\n"

        # Add instructions for structured output
        prompt += """
        Based on a thorough analysis of the user's query, logs, and code, please provide:

        1. **Issue Summary**: A clear explanation of what's causing the errors, incorporating insights from the user's query

        2. **Root Cause Analysis**: The fundamental issues in the code that are leading to these errors

        3. **Recommended Fixes**: For each file that needs changes, provide:
           - File path
           - Specific changes needed (original code and fixed code in markdown code blocks)
           - Explanation of why this fix works

        4. **Additional Recommendations**: Any broader suggestions to improve code quality or prevent similar issues

        Format your response in markdown with clear sections and code blocks for the fixes.
        Be thorough in your analysis and specific in your recommendations.
        """

        # Get fixes from LLM
        fixes_response = self.model.invoke([{"role": "system", "content": prompt}])

        return fixes_response.content

    def _generate_code_fix_report(self, logs: str, user_query: str, fixes: str,
                                file_contents: Dict[str, str]) -> str:
        """Generate a comprehensive code fix report.

        Args:
            logs: Log content
            user_query: User's original query
            fixes: Generated fix recommendations
            file_contents: File contents that were analyzed

        Returns:
            Formatted code fix report
        """
        report = "# Code Fix Recommendations\n\n"

        # Add an executive summary
        report += "## Executive Summary\n\n"

        summary_prompt = f"""
        Provide a brief executive summary (2-3 paragraphs) of the issues identified in the logs and user query,
        and the recommended fixes. Keep it concise but include the key insights from the user's original question.
        
        User Query:
        {user_query}
        
        Log Content (abbreviated):
        {logs[:500] + '...' if len(logs) > 500 else logs}
        """

        summary_response = self.model.invoke([{"role": "system", "content": summary_prompt}])
        report += f"{summary_response.content}\n\n"

        # Add the detailed fixes
        report += "## Detailed Analysis and Fixes\n\n"
        report += fixes

        # Add implementation steps
        report += "\n\n## Implementation Steps\n\n"

        implementation_prompt = f"""
        Based on the user's query and the fixes recommended, provide a step-by-step guide for implementing these changes safely. 
        Include any testing or validation steps that should be performed after making the changes.
        Address any specific concerns or priorities that might have been mentioned in the user's original query.
        
        User Query:
        {user_query}
        """

        implementation_response = self.model.invoke([{"role": "system", "content": implementation_prompt}])
        report += f"{implementation_response.content}\n\n"

        # Add potential future improvements section
        report += "\n\n## Future Improvements\n\n"

        future_improvements_prompt = f"""
        Based on your analysis of the code and the issues identified, suggest 3-5 broader improvements 
        that could help prevent similar issues in the future. These should go beyond the immediate fixes 
        and address architecture, coding practices, testing, or other aspects that could improve the system's
        robustness.
        
        Files analyzed:
        {', '.join(file_contents.keys())}
        
        User original request:
        {user_query}
        """

        future_improvements_response = self.model.invoke([{"role": "system", "content": future_improvements_prompt}])
        report += f"{future_improvements_response.content}\n\n"

        return report