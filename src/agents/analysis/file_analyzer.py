"""
File analyzer agent.

This module provides an agent that analyzes files in a repository
to understand their purpose and functionality.
"""

import os
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
import concurrent.futures

from src.core.agent_base import Agent
from src.utils.file_utils import read_file, get_file_type
from src.utils.concurrency import parallel_process_with_progress
from src.models.repository import Repository, FileInfo


class FileAnalyzerAgent(Agent):
    """Agent for analyzing files in a repository.

    This agent analyzes each file in the repository to understand
    its purpose, responsibilities, and key functionality.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the file analyzer agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and analyze repository files.

        Args:
            state: Current state containing the repository information

        Returns:
            Updated state with file descriptions
        """
        self.log_info("File Analyzer Agent: Starting file analysis")

        # Get file list from state
        file_list = self._get_file_list(state)
        if not file_list:
            self.log_error("File Analyzer Agent: No file list found in state")
            error_msg = "No file list found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get repository path
        repo_path = self._extract_repo_path(state)
        if not repo_path:
            self.log_error("File Analyzer Agent: No repository path found in state")
            error_msg = "No repository path found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get repository object if available
        repository = state.get("repository")

        # Select files to analyze
        files_to_analyze = self._select_files_to_analyze(file_list, repository)
        self.log_info(f"File Analyzer Agent: Selected {len(files_to_analyze)} files for analysis")

        if not files_to_analyze:
            self.log_warning("File Analyzer Agent: No files selected for analysis")
            message = "No files selected for analysis. Repository may be empty or contain only non-analyzable files."
            return self.add_message_to_state(state, message, "system", "file_descriptions")

        # Analyze files
        file_descriptions = self._analyze_files(files_to_analyze, repo_path)

        # Update repository object with descriptions if available
        if repository:
            for file_path, description in file_descriptions.items():
                file_info = repository.get_file(file_path)
                if file_info:
                    file_info.description = description
                    repository.mark_file_analyzed(file_path)

        # Format descriptions and add to state
        formatted_descriptions = self._format_descriptions(file_descriptions)
        state = self.add_message_to_state(
            state,
            f"File Descriptions: {formatted_descriptions}",
            "system",
            "file_descriptions"
        )

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("File Analyzer Agent: File analysis complete")
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
                continue

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

    def _select_files_to_analyze(self, file_list: List[str],
                                 repository: Optional[Repository] = None) -> List[str]:
        """Select files to analyze based on importance and file type.

        Args:
            file_list: List of all files
            repository: Optional repository object

        Returns:
            List of files to analyze
        """
        # Filter out binary files, very large files, and non-important files
        max_file_size = 1024 * 1024  # 1 MB

        # Define important file patterns
        important_patterns = [
            r'app\.(py|js|ts|go|java|rb|php)$',
            r'main\.(py|js|ts|go|java|rb|php)$',
            r'index\.(py|js|ts|go|java|rb|php|html)$',
            r'config\.(py|js|json|yaml|yml)$',
            r'settings\.(py|js|json|yaml|yml)$',
            r'README\.md$',
            r'setup\.py$',
            r'package\.json$',
            r'requirements\.txt$',
            r'go\.mod$',
            r'Dockerfile$',
            r'docker-compose\.yml$',
            r'\.gitignore$',
            r'Makefile$'
        ]

        # Define file types to analyze
        analyzable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.rb', '.php', '.go',
            '.cs', '.c', '.cpp', '.h', '.swift', '.kt', '.rs', '.scala', '.html',
            '.css', '.scss', '.less', '.json', '.xml', '.yaml', '.yml', '.md',
            '.txt', '.sql', '.sh', '.bat', '.ps1', '.Dockerfile', '.Makefile'
        }

        # Filter files
        selected_files = []

        for file_path in file_list:
            # Use repository object if available
            if repository:
                file_info = repository.get_file(file_path)
                if file_info:
                    if (file_info.is_binary or
                            file_info.size > max_file_size or
                            file_info.extension not in analyzable_extensions):
                        continue
            else:
                # Skip based on file extension if repository object not available
                ext = os.path.splitext(file_path)[1].lower()
                if ext not in analyzable_extensions:
                    continue

            # Check if this is an important file
            is_important = any(re.search(pattern, file_path, re.IGNORECASE)
                               for pattern in important_patterns)

            if is_important:
                # Add important files to the beginning of the list
                selected_files.insert(0, file_path)
            else:
                selected_files.append(file_path)

        # Limit to a reasonable number of files (e.g., 50)
        max_files = 1000
        if len(selected_files) > max_files:
            self.log_info(f"Limiting analysis to {max_files} files out of {len(selected_files)}")
            # Keep important files at the beginning
            important_count = sum(1 for file in selected_files[:max_files]
                                  if any(re.search(pattern, file, re.IGNORECASE)
                                         for pattern in important_patterns))

            # Keep some non-important files for diversity
            remaining_slots = max_files - important_count
            if remaining_slots > 0:
                selected_files = (
                        selected_files[:important_count] +
                        selected_files[important_count:important_count + remaining_slots]
                )
            else:
                selected_files = selected_files[:max_files]

        return selected_files

    def _analyze_files(self, files: List[str], repo_path: str) -> Dict[str, str]:
        """Analyze files in parallel.

        Args:
            files: List of files to analyze
            repo_path: Repository root path

        Returns:
            Dictionary mapping file paths to descriptions
        """
        self.log_info(f"Analyzing {len(files)} files")

        # Process files in parallel
        file_descriptions = {}

        try:
            # Create a function to process one file
            def process_file(file_path):
                try:
                    full_path = os.path.join(repo_path, file_path)
                    return file_path, self._analyze_file(full_path, file_path)
                except Exception as e:
                    self.log_error(f"Error analyzing {file_path}: {str(e)}")
                    return file_path, f"Error analyzing file: {str(e)}"

            # Use parallel processing with progress reporting
            results = parallel_process_with_progress(
                process_file,
                files,
                max_workers=10,
                desc="Analyzing files"
            )

            # Collect results
            for file_path, description in results:
                if description:  # Skip None results
                    file_descriptions[file_path] = description

        except Exception as e:
            self.log_error(f"Error during parallel file analysis: {str(e)}")

        return file_descriptions

    def _analyze_file(self, full_file_path: str, rel_file_path: str) -> str:
        """Analyze a single file.

        Args:
            full_file_path: Full path to the file
            rel_file_path: Path relative to repository root

        Returns:
            Description of the file
        """
        self.log_debug(f"Analyzing file: {rel_file_path}")

        # Read file content
        file_content = read_file(full_file_path)
        if not file_content:
            return f"Could not read file content"

        # Determine file type
        file_type = get_file_type(full_file_path)

        # Create prompt for analysis
        prompt = f"""
        You are analyzing a file that is part of a larger framework or application. The goal is to help
        a developer new to this codebase quickly understand the file's purpose and functionality.

        Please include:
        1. A concise statement of this file's core responsibilities.
        2. How it interacts with or depends on other parts of the codebase.
        3. Any key classes, functions, or patterns implemented.
        4. Recommendations on how a developer might extend or modify this file.

        File: {rel_file_path}
        File Type: {file_type}

        Content:
        {file_content[:50000]}  # Limit content to 50,000 characters
        """

        # Get analysis from LLM
        response = self.model.invoke([{"role": "system", "content": prompt}])
        description = response.content

        # Format the description
        return f"{description}"

    def _format_descriptions(self, file_descriptions: Dict[str, str]) -> str:
        """Format file descriptions for output.

        Args:
            file_descriptions: Dictionary mapping file paths to descriptions

        Returns:
            Formatted descriptions string
        """
        result = ""
        for file_path, description in file_descriptions.items():
            result += f"File: {file_path}\n{description}\n\n---\n\n"

        return result