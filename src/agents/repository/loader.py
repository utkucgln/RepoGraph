"""
Repository loader agent.

This module provides an agent that loads and scans repositories,
identifying all files and their properties.
"""

import os
import logging
from typing import Dict, Any, List, Optional

from src.core.agent_base import Agent
from src.utils.file_utils import get_all_files, get_file_type, is_binary_file, get_file_info
from src.models.repository import Repository, FileInfo, DirectoryInfo
from pathlib import Path


class RepositoryLoaderAgent(Agent):
    """Agent for loading and scanning repositories.

    This agent is responsible for scanning a repository, identifying
    all files, and extracting their properties.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the repository loader agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and load the repository.

        Args:
            state: Current state containing the repository path

        Returns:
            Updated state with repository information
        """
        self.log_info("Repository Loader Agent: Starting repository loading")

        # Extract repository path from state
        repo_path = self._extract_repo_path(state)
        if not repo_path:
            self.log_error("Repository Loader Agent: No repository path found in state")
            error_msg = "No repository path specified. Please provide a path using 'Path: /path/to/repo'"
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Validate repository path
        if not os.path.isdir(repo_path):
            self.log_error(f"Repository Loader Agent: Invalid repository path: {repo_path}")
            error_msg = f"Invalid repository path: {repo_path}. Path does not exist or is not a directory."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Load and scan the repository
        try:
            files, repo = self._load_repository(repo_path)
            self.log_info(f"Repository Loader Agent: Loaded {len(files)} files from {repo_path}")

            # Add repository information to state
            state = self._update_state_with_repository_info(state, files, repo)

            # Mark this stage as complete
            if "completed_stages" not in state:
                state["completed_stages"] = []
            if self.name not in state["completed_stages"]:
                state["completed_stages"].append(self.name)

            return state

        except Exception as e:
            self.log_error(f"Repository Loader Agent: Error loading repository: {str(e)}")
            error_msg = f"Error loading repository: {str(e)}"
            return self.add_message_to_state(state, error_msg, "system", "error")

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

    def _load_repository(self, repo_path: str) -> tuple:
        """Load and scan the repository.

        Args:
            repo_path: Path to the repository

        Returns:
            Tuple of (files, repository_object)
        """
        self.log_info(f"Loading repository from path: {repo_path}")

        # Get all files in the repository
        files = get_all_files(repo_path, ignore_gitignore=True)

        # Create a Repository object
        repo_name = os.path.basename(os.path.abspath(repo_path))
        repository = Repository(
            path=repo_path,
            name=repo_name,
            root_directory=DirectoryInfo(path=repo_path, name=repo_name)
        )

        # Process each file
        for file_path in files:
            try:
                # Get relative path for better display
                rel_path = os.path.relpath(file_path, repo_path)

                # Get file info
                file_info = self._process_file(file_path, repo_path)

                # Add to repository
                repository.add_file(file_info)

            except Exception as e:
                self.log_warning(f"Error processing file {file_path}: {str(e)}")

        # Build directory structure (simplified for now)
        self._build_directory_structure(repository)

        return files, repository

    def _process_file(self, file_path: str, repo_path: str) -> FileInfo:
        """Process a file and extract its information.

        Args:
            file_path: Path to the file
            repo_path: Repository root path

        Returns:
            FileInfo object with file details
        """
        rel_path = os.path.relpath(file_path, repo_path)

        # Get basic file info
        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_name)[1]
        file_size = os.path.getsize(file_path)
        file_type = get_file_type(file_path)
        is_binary = is_binary_file(file_path)

        return FileInfo(
            path=rel_path,
            name=file_name,
            extension=file_extension,
            size=file_size,
            is_binary=is_binary,
            type=file_type
        )

    def _build_directory_structure(self, repository: Repository) -> None:
        """Build the directory structure for the repository.

        Args:
            repository: Repository object to update
        """
        # This is a simplified implementation
        # A more complete implementation would build a proper directory tree

        # Group files by directory
        directories = {}

        for file_path, file_info in repository.all_files.items():
            dir_path = os.path.dirname(file_path)
            if dir_path not in directories:
                directories[dir_path] = []

            directories[dir_path].append(file_info)

        # Create directory objects
        dir_objects = {}

        for dir_path, files in directories.items():
            dir_name = os.path.basename(dir_path) or repository.name
            dir_objects[dir_path] = DirectoryInfo(
                path=dir_path,
                name=dir_name,
                files=files
            )

        # Set subdirectories
        for dir_path, dir_obj in dir_objects.items():
            parent_path = os.path.dirname(dir_path)
            if parent_path in dir_objects:
                dir_objects[parent_path].subdirectories.append(dir_obj)

        # Set root directory
        root_files = directories.get("", [])
        repository.root_directory = DirectoryInfo(
            path="",
            name=repository.name,
            files=root_files,
            subdirectories=[dir_obj for dir_path, dir_obj in dir_objects.items()
                            if "/" not in dir_path and dir_path != ""]
        )

    def _update_state_with_repository_info(self, state: Dict[str, Any],
                                           files: List[str], repository: Repository) -> Dict[str, Any]:
        """Update the state with repository information.

        Args:
            state: Current state
            files: List of file paths
            repository: Repository object

        Returns:
            Updated state
        """
        # Add file list to state in a format compatible with the original implementation
        file_list_message = "Files:\n" + "\n".join(files)
        state = self.add_message_to_state(state, file_list_message, "system", "file_list")

        # Add repository object to state
        if "repository" not in state:
            state["repository"] = repository

        # Add repository metadata
        file_stats = {
            "total_files": len(files),
            "by_extension": repository.get_file_extensions(),
            "by_language": repository.get_languages()
        }
        state = self.add_message_to_state(
            state,
            f"{file_stats}",
            "system",
            "repository_stats"
        )

        return state