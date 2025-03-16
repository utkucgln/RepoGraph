"""
Peer review agent.

This module provides an agent that performs comprehensive peer reviews
of repositories to evaluate code quality and maintainability.
"""

import os
import re
import logging
import json
import random
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from src.core.agent_base import Agent
from src.utils.file_utils import read_file, get_file_type
from src.utils.logging_utils import log_execution_time


class PeerReviewAgent(Agent):
    """Agent for performing comprehensive peer reviews.

    This agent analyzes repository code to evaluate its quality,
    maintainability, readability, and adherence to best practices.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the peer review agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and perform a peer review.

        Args:
            state: Current state containing repository information

        Returns:
            Updated state with peer review report
        """
        self.log_info("Peer Review Agent: Starting peer review")

        # Get file list and repository path
        file_list = self._get_file_list(state)
        repo_path = self._extract_repo_path(state)

        if not file_list:
            self.log_error("Peer Review Agent: No file list found in state")
            error_msg = "No file list found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        if not repo_path:
            self.log_error("Peer Review Agent: No repository path found in state")
            error_msg = "No repository path found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get file descriptions if available
        file_descriptions = self._get_file_descriptions(state)

        # Extract repository structure and context
        repo_context = self._extract_repository_context(state, file_list)

        # Select files for detailed review
        files_to_review = self._select_files_for_review(file_list, repo_context, repo_path)

        # Read file contents for detailed review
        file_contents = self._read_files_for_review(files_to_review, repo_path)

        # Perform the peer review
        review_findings = self._perform_peer_review(file_contents, repo_context, file_descriptions)

        # Generate the peer review report
        report = self._generate_peer_review_report(review_findings, repo_context)

        # Add report to state
        state = self.add_message_to_state(
            state,
            report,
            "system",
            "peer_review"
        )

        # Save report to file if output directory exists
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Get the repository name from the path

        report_path = os.path.join(output_dir, "peer_review.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        self.log_info(f"Report saved to {report_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Peer Review Agent: Review complete")
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

    def _extract_repository_context(self, state: Dict[str, Any],
                                    file_list: List[str]) -> Dict[str, Any]:
        """Extract repository context for peer review.

        Args:
            state: Current state
            file_list: List of file paths

        Returns:
            Dictionary with repository context
        """
        context = {}

        # Get extension statistics
        extensions = {}
        for file_path in file_list:
            ext = Path(file_path).suffix.lower()
            if ext:
                extensions[ext] = extensions.get(ext, 0) + 1

        context["extensions"] = extensions

        # Get language statistics based on extensions
        languages = {}
        ext_to_language = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "React JSX",
            ".tsx": "React TSX",
            ".java": "Java",
            ".rb": "Ruby",
            ".php": "PHP",
            ".go": "Go",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".rs": "Rust",
            ".scala": "Scala"
        }

        for ext, count in extensions.items():
            if ext in ext_to_language:
                lang = ext_to_language[ext]
                languages[lang] = languages.get(lang, 0) + count

        context["languages"] = languages

        # Extract main languages (top 3)
        context["main_languages"] = [lang for lang, _ in
                                     sorted(languages.items(), key=lambda x: x[1], reverse=True)[:3]]

        # Get directory structure
        directories = {}
        for file_path in file_list:
            dir_path = os.path.dirname(file_path)
            if dir_path not in directories:
                directories[dir_path] = []
            directories[dir_path].append(file_path)

        context["directories"] = directories

        # Identify key directories (having most files)
        context["key_directories"] = [dir_path for dir_path, _ in
                                      sorted(directories.items(), key=lambda x: len(x[1]), reverse=True)[:10]]

        # Find test directories and files
        test_files = [f for f in file_list if re.search(r'test|spec', f, re.IGNORECASE)]
        test_directories = [d for d in directories.keys() if re.search(r'test|spec', d, re.IGNORECASE)]

        context["test_files"] = test_files
        context["test_directories"] = test_directories

        # Find configuration files
        config_files = [f for f in file_list if
                        re.search(r'config|settings|\.env|\.json|\.yaml|\.yml|\.toml|\.ini', f, re.IGNORECASE)]

        context["config_files"] = config_files

        return context

    def _select_files_for_review(self, file_list: List[str],
                                 repo_context: Dict[str, Any],
                                 repo_path: str) -> List[str]:
        """Select files for detailed review based on importance, complexity, and type.

        This enhanced selection method uses the LLM to analyze file characteristics and
        identify the most representative and critical files for review. It combines
        algorithmic filtering with LLM-based importance assessment.

        Args:
            file_list: List of all files
            repo_context: Repository context
            repo_path: Repository path

        Returns:
            List of files to review
        """
        import math
        from collections import Counter

        self.log_info("Starting enhanced file selection for peer review")

        # Define file types to analyze
        analyzable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.rb', '.php', '.go',
            '.cs', '.c', '.cpp', '.h', '.swift', '.kt', '.rs', '.scala', '.html',
            '.css', '.scss', '.less', '.md', '.sql', '.yaml', '.yml', '.json', '.toml'
        }

        # Define mapping from extensions to languages
        ext_to_language = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "React JSX",
            ".tsx": "React TSX",
            ".java": "Java",
            ".rb": "Ruby",
            ".php": "PHP",
            ".go": "Go",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".h": "C/C++ Header",
            ".rs": "Rust",
            ".scala": "Scala",
            ".html": "HTML",
            ".css": "CSS",
            ".scss": "SCSS",
            ".less": "Less",
            ".md": "Markdown",
            ".sql": "SQL",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".json": "JSON",
            ".toml": "TOML"
        }

        # Step 1: Filter out binary files, non-code files, and third-party code
        filtered_files = []
        for file_path in file_list:
            # Skip binary files and very large files
            if file_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                                   '.woff', '.woff2', '.ttf', '.eot', '.otf', '.pdf',
                                   '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
                                   '.class', '.pyc', '.pyo', '.o', '.obj', '.exe',
                                   '.dll', '.so', '.dylib', '.jar')):
                continue

            # Skip node_modules, virtual environments, and other non-source directories
            if any(part in file_path for part in ['/node_modules/', '/venv/', '/.venv/',
                                                  '/env/', '/dist/', '/build/', '/.git/',
                                                  '/vendor/', '/third_party/', '/third-party/',
                                                  '/__pycache__/', '/bin/', '/obj/']):
                continue

            # Check extension
            ext = Path(file_path).suffix.lower()
            if ext not in analyzable_extensions:
                continue

            filtered_files.append(file_path)

        self.log_info(f"Filtered to {len(filtered_files)} relevant files")

        # Step 2: Get basic metrics for filtered files
        file_metrics = {}
        dir_file_counts = Counter()

        for file_path in filtered_files:
            try:
                # Get file size
                full_path = os.path.join(repo_path, file_path)
                file_size = os.path.getsize(full_path)

                # Get line count (basic complexity indicator)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        line_count = content.count('\n') + 1

                        # Calculate content preview for LLM analysis
                        preview_lines = content.split('\n')[:50]  # First 50 lines for preview
                        content_preview = '\n'.join(preview_lines)

                        if len(content_preview) > 2000:
                            content_preview = content_preview[:2000] + "... (truncated)"

                        # Track parent directory
                        dir_path = os.path.dirname(file_path)
                        dir_file_counts[dir_path] += 1

                        file_metrics[file_path] = {
                            'size': file_size,
                            'lines': line_count,
                            'content_preview': content_preview,
                            'dir_path': dir_path,
                            'extension': ext
                        }
                except Exception as e:
                    self.log_error(f"Error reading {file_path}: {str(e)}")
                    # Still include file with basic metrics
                    file_metrics[file_path] = {
                        'size': file_size,
                        'lines': 0,
                        'content_preview': "(Unable to read file content)",
                        'dir_path': os.path.dirname(file_path),
                        'extension': ext
                    }
            except Exception as e:
                self.log_error(f"Error getting size for {file_path}: {str(e)}")

        # Step 3: Group files by language/type for batch analysis
        language_groups = {}
        for file_path, metrics in file_metrics.items():
            ext = metrics['extension']
            lang = ext_to_language.get(ext, "Other")

            if lang not in language_groups:
                language_groups[lang] = []

            # Add file to its language group
            language_groups[lang].append(file_path)

        # Step 4: Create a repo overview for the LLM
        repo_summary = {
            'file_counts_by_language': {},
            'main_languages': repo_context.get('main_languages', []),
            'test_files_count': len(repo_context.get('test_files', [])),
            'config_files_count': len(repo_context.get('config_files', [])),
            'top_directories': repo_context.get('key_directories', [])[:5],
        }

        # Count files by language
        for lang, files in language_groups.items():
            repo_summary['file_counts_by_language'][lang] = len(files)

        # Step 5: Use the LLM to analyze files by language groups
        file_importance_scores = {}
        file_categories = {}

        for lang, files in language_groups.items():
            self.log_info(f"Analyzing {len(files)} {lang} files with LLM")

            # Skip if too many files in this group - analyze subgroups
            if len(files) > 20:
                # Create smaller batches
                batch_size = 20
                for i in range(0, len(files), batch_size):
                    batch = files[i:i + batch_size]
                    self._analyze_files_batch(batch, file_metrics, repo_summary, file_importance_scores,
                                              file_categories)
            else:
                self._analyze_files_batch(files, file_metrics, repo_summary, file_importance_scores, file_categories)

        # Step 6: Calculate directory importance based on file scores
        dir_importance = {}
        dir_files = {}

        for file_path, importance in file_importance_scores.items():
            dir_path = file_metrics[file_path]['dir_path']
            if dir_path not in dir_files:
                dir_files[dir_path] = []
            dir_files[dir_path].append((file_path, importance))

        for dir_path, files in dir_files.items():
            if files:
                total_importance = sum(imp for _, imp in files)
                avg_importance = total_importance / len(files)
                max_importance = max(imp for _, imp in files)
                dir_importance[dir_path] = (avg_importance + max_importance) / 2  # Balance average and peak importance

        # Step 7: Use LLM to select the final set of files based on all collected data
        selection_quota = min(1000, len(filtered_files))  # Limit to 30 files max

        # Prepare file data for selection
        file_data = []
        for file_path, importance in file_importance_scores.items():
            metrics = file_metrics[file_path]
            category = file_categories.get(file_path, "Unknown")
            dir_imp = dir_importance.get(metrics['dir_path'], 0)

            file_data.append({
                'path': file_path,
                'importance': importance,
                'category': category,
                'lines': metrics['lines'],
                'size': metrics['size'],
                'directory': metrics['dir_path'],
                'dir_importance': dir_imp,
                'language': ext_to_language.get(metrics['extension'], "Unknown")
            })

        selected_files = self._llm_select_diverse_files(file_data, repo_summary, selection_quota)

        self.log_info(f"Selected {len(selected_files)} files for detailed review")
        return selected_files

    def _analyze_files_batch(self, files_batch: List[str],
                             file_metrics: Dict[str, Dict],
                             repo_summary: Dict[str, Any],
                             file_importance_scores: Dict[str, float],
                             file_categories: Dict[str, str]):
        """Analyze a batch of files using the LLM to determine importance and categories.

        Args:
            files_batch: List of file paths to analyze
            file_metrics: Dictionary containing metrics for each file
            repo_summary: Summary of repository statistics
            file_importance_scores: Dictionary to store importance scores (modified in-place)
            file_categories: Dictionary to store file categories (modified in-place)
        """
        # Prepare batch data for LLM
        batch_data = []
        for file_path in files_batch:
            metrics = file_metrics[file_path]
            batch_data.append({
                'path': file_path,
                'size_bytes': metrics['size'],
                'line_count': metrics['lines'],
                'extension': metrics['extension'],
                'content_preview': metrics['content_preview']
            })

        # Create the prompt for file analysis
        prompt = f"""
        You are a code review expert analyzing a batch of files from a software repository to identify which files are most important for a peer review.

        Repository Overview:
        - Main languages: {', '.join(repo_summary['main_languages'])}
        - File counts by language: {repo_summary['file_counts_by_language']}
        - Test files: {repo_summary['test_files_count']}
        - Config files: {repo_summary['config_files_count']}
        - Key directories: {', '.join(repo_summary['top_directories'])}

        For each file, analyze:
        1. Its likely role in the codebase (e.g., core logic, utility, configuration, etc.)
        2. Its importance for peer review on a scale of 0-100 
        3. Why it matters (or doesn't) for code quality assessment
        4. A category label (one of: "Core", "Configuration", "Utility", "Test", "Frontend", "Backend", "Database", "Security", "Documentation", "Build")

        Consider these factors when evaluating importance:
        - Entry points and critical path code should have high importance
        - Files with security implications should have high importance
        - Core business logic should have high importance
        - Configuration files that affect the entire system should have moderate to high importance
        - Complex utility functions should have moderate importance
        - Simple helper functions should have lower importance
        - Test files should have moderate importance if they reveal architecture, lower otherwise

        Format your response as a valid JSON array with objects containing 'path', 'importance', 'category', and 'rationale' for each file.

        Files to analyze:
        ```
        {batch_data}
        ```
        """

        # Get evaluation from LLM
        try:
            evaluation_response = self.model.invoke([{"role": "system", "content": prompt}])

            # Extract JSON from the response
            json_pattern = r'```(?:json)?\n(.*?)\n```'
            match = re.search(json_pattern, evaluation_response.content, re.DOTALL)

            if match:
                analysis_results = json.loads(match.group(1))
            else:
                # If no code block, try to parse the whole response
                analysis_results = json.loads(evaluation_response.content)

            # Process the results
            for result in analysis_results:
                file_path = result.get('path')
                importance = result.get('importance')
                category = result.get('category')

                if file_path and importance is not None:
                    file_importance_scores[file_path] = float(importance)

                if file_path and category:
                    file_categories[file_path] = category

        except Exception as e:
            self.log_error(f"Error in LLM analysis of file batch: {str(e)}")

    def _llm_select_diverse_files(self, file_data: List[Dict],
                                  repo_summary: Dict[str, Any],
                                  selection_quota: int) -> List[str]:
        """Use the LLM to select a diverse set of files for review based on all collected data.

        Args:
            file_data: Data about files including importance scores and categories
            repo_summary: Summary of repository statistics
            selection_quota: Maximum number of files to select

        Returns:
            List of selected file paths
        """
        # Sort files by importance to show the most important ones first
        sorted_file_data = sorted(file_data, key=lambda x: x['importance'], reverse=True)

        # If there are too many files, only show the top ones to the LLM
        max_files_to_display = 1000  # Limit for context length
        if len(sorted_file_data) > max_files_to_display:
            displayed_files = sorted_file_data[:max_files_to_display]
        else:
            displayed_files = sorted_file_data

        # Create prompt for file selection
        prompt = f"""
        You are a code review expert selecting files for a comprehensive peer review of a software repository.

        Repository Overview:
        - Main languages: {', '.join(repo_summary['main_languages'])}
        - File counts by language: {repo_summary['file_counts_by_language']}
        - Test files: {repo_summary['test_files_count']}
        - Config files: {repo_summary['config_files_count']}
        - Key directories: {', '.join(repo_summary['top_directories'])}

        Your task is to select exactly {selection_quota} files from the given list that will provide the most comprehensive view of:
        1. Code quality
        2. Architecture
        3. Security practices
        4. Maintainability
        5. Testing approach

        Selection criteria:
        - Must include high-importance files (typically scored 70+)
        - Should represent all major languages in the repository
        - Should include files from different categories (Core, Configuration, Security, etc.)
        - Should include files from important directories
        - Should include a balance of large/complex files and smaller critical files
        - Must mention reference points for code quality, architecture, and security in your selection rationale

        Files are sorted by importance (higher is more important).
        {f"Note: Only the top {max_files_to_display} files by importance are shown due to context limits." if len(file_data) > max_files_to_display else ""}

        Available files:
        ```
        {displayed_files}
        ```

        Respond with a JSON array containing ONLY the paths of the {selection_quota} selected files. Format: ["path1", "path2", ...].
        Also include a brief explanation of your selection strategy.
        """

        # Get selection from LLM
        try:
            selection_response = self.model.invoke([{"role": "system", "content": prompt}])

            # Extract JSON from the response
            json_pattern = r'```(?:json)?\n(.*?)\n```'
            match = re.search(json_pattern, selection_response.content, re.DOTALL)

            if match:
                selected_paths = json.loads(match.group(1))
            else:
                # Try to extract array directly from content (without code block)
                array_pattern = r'\[(.*?)\]'
                match = re.search(array_pattern, selection_response.content, re.DOTALL)
                if match:
                    array_content = match.group(1)
                    # Clean and parse the array content
                    selected_paths = json.loads(f"[{array_content}]")
                else:
                    # Fallback to manual extraction if JSON parsing fails
                    self.log_info("LLM selection couldn't be parsed as JSON, using fallback extraction")

                    # Extract paths enclosed in quotes
                    path_pattern = r'"([^"]+)"'
                    selected_paths = re.findall(path_pattern, selection_response.content)

            # Validate and limit selection
            valid_paths = [path for path in selected_paths if path in [f['path'] for f in file_data]]

            # Deduplicate
            valid_paths = list(dict.fromkeys(valid_paths))

            # Limit to selection quota
            if len(valid_paths) > selection_quota:
                valid_paths = valid_paths[:selection_quota]

            # If we have fewer files than quota, add more from the sorted list
            if len(valid_paths) < selection_quota:
                additional_needed = selection_quota - len(valid_paths)
                for file_info in sorted_file_data:
                    path = file_info['path']
                    if path not in valid_paths:
                        valid_paths.append(path)
                        additional_needed -= 1
                        if additional_needed <= 0:
                            break

            self.log_info(f"LLM selected {len(valid_paths)} files for review")
            return valid_paths

        except Exception as e:
            self.log_error(f"Error in LLM file selection: {str(e)}")

            # Fallback to algorithmic selection
            self.log_info("Using fallback algorithmic selection")

            # Sort by importance and select top files
            sorted_paths = [f['path'] for f in sorted(file_data, key=lambda x: x['importance'], reverse=True)]
            selected = sorted_paths[:selection_quota]

            return selected
    def _read_files_for_review(self, files: List[str], repo_path: str) -> Dict[str, str]:
        """Read contents of files for detailed review.

        Args:
            files: List of files to read
            repo_path: Repository path

        Returns:
            Dictionary mapping file paths to their content
        """
        file_contents = {}

        for file_path in files:
            try:
                full_path = os.path.join(repo_path, file_path)
                content = read_file(full_path)

                if content:
                    # Limit content size to prevent LLM token limits
                    if len(content) > 10000:
                        content = content[:10000] + "\n\n... (file truncated due to size)"

                    file_contents[file_path] = content

            except Exception as e:
                self.log_error(f"Error reading {file_path}: {str(e)}")

        return file_contents

    def _get_static_checklist(self) -> Dict[str, List[str]]:
        """Get the static (default) review checklist.

        Returns:
            Dictionary with categories as keys and checklist items as values
        """
        # This is the original static checklist that will be used as fallback
        return {
            "Code Organization": [
                "Follows a consistent and logical directory structure",
                "Separates concerns with clear module boundaries",
                "Uses appropriate design patterns for the problem domain",
                "Avoids excessive nesting of directories",
                "Groups related functionality together"
            ],
            "Code Quality": [
                "Uses meaningful and consistent naming conventions",
                "Includes appropriate comments and documentation",
                "Follows consistent formatting and style",
                "Avoids code duplication (DRY principle)",
                "Keeps functions/methods focused and concise",
                "Handles errors and edge cases appropriately",
                "Avoids magic numbers and hardcoded values"
            ],
            # ... [rest of the original checklist remains unchanged]
        }

    def _generate_dynamic_checklist(self, repo_context: Dict[str, Any], file_contents: Dict[str, str]) -> Dict[
        str, List[str]]:
        """Generate a dynamic review checklist based on repository content.

        Args:
            repo_context: Repository context information
            file_contents: Dictionary of file contents for analysis

        Returns:
            Dictionary with categories as keys and checklist items as values
        """
        self.log_info("Generating dynamic review checklist")

        # Extract key information for prompting
        languages = repo_context.get("main_languages", [])
        language_str = ", ".join(languages[:3]) if languages else "Unknown"

        # Count file types
        file_types = {}
        for file_path in file_contents.keys():
            ext = Path(file_path).suffix.lower()
            file_types[ext] = file_types.get(ext, 0) + 1

        # Determine if repository has tests
        has_tests = len(repo_context.get("test_files", [])) > 0

        # Determine if repository has configuration files
        has_config = len(repo_context.get("config_files", [])) > 0

        # Get a sample of file paths to help the LLM understand the repo structure
        sample_paths = list(file_contents.keys())[:10]
        path_samples = "\n".join(f"- {path}" for path in sample_paths)

        # Sample some file content to identify patterns and conventions
        content_samples = ""
        for path, content in list(file_contents.items())[:3]:
            # Limit content sample size
            preview = content[:1000] + "..." if len(content) > 1000 else content
            content_samples += f"\n--- {path} ---\n{preview}\n"

        # Define review categories
        categories = [
            "Code Organization",
            "Code Quality",
            "Architecture",
            "Performance",
            "Security",
            "Testing",
            "Documentation",
            "Maintainability",
            "Best Practices"
        ]

        # Build the prompt for checklist generation
        prompt = f"""
        You are a code review expert. Generate a comprehensive review checklist tailored to this specific repository.

        Repository Information:
        - Main languages: {language_str}
        - Has tests: {'Yes' if has_tests else 'No'}
        - Has configuration files: {'Yes' if has_config else 'No'}
        - File types: {dict(file_types)}

        Sample file paths:
        {path_samples}

        Sample file content for pattern identification:
        {content_samples}

        For each of the following categories, generate 5-8 specific checklist items that are:
        1. Relevant to this repository's specific tech stack and structure
        2. Concrete and assessable (can be clearly evaluated as met or not met)
        3. Adapted to the repository's observed coding patterns and conventions

        Categories: {', '.join(categories)}

        Respond with a JSON structure like:
        {{
            "Code Organization": ["Item 1", "Item 2", ...],
            "Code Quality": ["Item 1", "Item 2", ...],
            ...
        }}

        Include language-specific best practices where appropriate.
        """

        try:
            # Get checklist from LLM
            self.log_info("Querying LLM for dynamic checklist")
            checklist_response = self.model.invoke([{"role": "system", "content": prompt}])

            # Extract JSON from the response
            json_pattern = r'```(?:json)?\n(.*?)\n```'
            match = re.search(json_pattern, checklist_response.content, re.DOTALL)

            if match:
                dynamic_checklist = json.loads(match.group(1))
            else:
                # If no code block, try to parse the whole response
                dynamic_checklist = json.loads(checklist_response.content)

            # Ensure all categories are present
            for category in categories:
                if category not in dynamic_checklist:
                    dynamic_checklist[category] = [
                        f"Follows {category.lower()} best practices",
                        f"Implements {category.lower()} standards consistently"
                    ]

            self.log_info(
                f"Generated dynamic checklist with {sum(len(items) for items in dynamic_checklist.values())} items")
            return dynamic_checklist

        except Exception as e:
            self.log_error(f"Error generating dynamic checklist: {str(e)}")
            # Fall back to static checklist if generation fails
            return self._get_static_checklist()



    def _perform_peer_review(self, file_contents: Dict[str, str],
                             repo_context: Dict[str, Any],
                             file_descriptions: Optional[str] = None) -> Dict[str, Any]:
        """Perform peer review on selected files.

        Args:
            file_contents: Dictionary of file contents
            repo_context: Repository context
            file_descriptions: Optional file descriptions

        Returns:
            Dictionary with review findings
        """

        review_checklist = self._generate_dynamic_checklist(repo_context, file_contents)

        # Define review categories based on the checklist
        review_categories = list(review_checklist.keys())

        # Assess each review category
        category_assessments = {}

        for category in review_categories:
            checklist_items = review_checklist[category]

            # Create context for this category
            category_files = {}

            # Include relevant files for this category
            for file_path, content in file_contents.items():
                # Determine if this file is relevant for this category
                is_relevant = False

                if category == "Code Organization":
                    # All files are relevant for organization
                    is_relevant = True
                elif category == "Code Quality":
                    # Source code files are relevant
                    is_relevant = Path(file_path).suffix.lower() in ['.py', '.js', '.ts', '.jsx', '.tsx',
                                                                     '.java', '.rb', '.php', '.go', '.cs']
                elif category == "Architecture":
                    # Core application files are relevant
                    is_relevant = any(pattern in file_path.lower() for pattern in
                                      ['app', 'main', 'core', 'service', 'controller', 'model'])
                elif category == "Performance":
                    # Files with potential performance implications
                    is_relevant = any(pattern in file_path.lower() for pattern in
                                      ['service', 'worker', 'process', 'compute', 'cache'])
                elif category == "Security":
                    # Files with security implications
                    is_relevant = any(pattern in file_path.lower() for pattern in
                                      ['auth', 'login', 'user', 'password', 'token', 'security'])
                elif category == "Testing":
                    # Test files
                    is_relevant = 'test' in file_path.lower() or 'spec' in file_path.lower()
                elif category == "Documentation":
                    # Documentation files
                    is_relevant = file_path.lower().endswith(('.md', '.rst', '.txt')) or 'doc' in file_path.lower()
                elif category == "Maintainability":
                    # All source code files
                    is_relevant = Path(file_path).suffix.lower() in ['.py', '.js', '.ts', '.jsx', '.tsx',
                                                                     '.java', '.rb', '.php', '.go', '.cs']
                elif category == "Best Practices":
                    # All source code files
                    is_relevant = Path(file_path).suffix.lower() in ['.py', '.js', '.ts', '.jsx', '.tsx',
                                                                     '.java', '.rb', '.php', '.go', '.cs']

                if is_relevant:
                    category_files[file_path] = content

            # If no relevant files, use a sample
            if not category_files and file_contents:
                # Take up to 3 random files
                sample_size = min(3, len(file_contents))
                sample_files = random.sample(list(file_contents.items()), sample_size)
                category_files = dict(sample_files)

            # Create prompt for this category
            prompt = f"""
            You are conducting a detailed peer review of a software repository. 
            Please evaluate the codebase against the following checklist items for the category '{category}':

            {os.linesep.join(f"- {item}" for item in checklist_items)}

            Here are some relevant files for the '{category}' category:
            """

            # Add file contents
            for file_path, content in category_files.items():
                prompt += f"\n--- {file_path} ---\n{content}\n\n"

            # Add repository context
            prompt += f"""
            Repository Context:
            - Main Languages: {', '.join(repo_context.get('main_languages', ['Unknown']))}
            - Test Files: {len(repo_context.get('test_files', []))}
            - Config Files: {len(repo_context.get('config_files', []))}

            For each checklist item, provide:
            1. A clear evaluation (Meets Standard, Needs Improvement, Major Concern, Not Applicable)
            2. Specific examples or evidence from the code
            3. Recommendations for improvement if needed

            Format your response as a JSON object with the following structure:
            ```json
            {{
            "items": [
                {{
            "criterion": "[Checklist item text]",
                  "evaluation": "[Meets Standard/Needs Improvement/Major Concern/Not Applicable]",
                  "evidence": "[Specific examples from the code]",
                  "recommendations": "[Recommendations for improvement]"
                }},
                ...
              ]
            }}
            ```

            Be specific, objective, and provide concrete examples in your evaluation.
            """

            # Get evaluation from LLM
            self.log_info(f"Evaluating {category} category")
            evaluation_response = self.model.invoke([{"role": "system", "content": prompt}])

            # Parse the response
            try:
                # Extract JSON from the response
                json_pattern = r'```(?:json)?\n(.*?)\n```'
                match = re.search(json_pattern, evaluation_response.content, re.DOTALL)

                if match:
                    category_results = json.loads(match.group(1))
                else:
                    # If no code block, try to parse the whole response
                    category_results = json.loads(evaluation_response.content)

                # Add category information
                category_results["category"] = category
                category_assessments[category] = category_results

            except Exception as e:
                self.log_error(f"Error parsing evaluation for {category}: {str(e)}")
                category_assessments[category] = {
                    "category": category,
                    "error": f"Error parsing evaluation: {str(e)}",
                    "items": []
                }

        # Generate overall assessment and recommendations
        findings = {
            "category_assessments": category_assessments,
            "evaluation_summary": self._summarize_evaluations(category_assessments),
            "recommendations": self._generate_recommendations(category_assessments, repo_context)
        }

        return findings

    def _summarize_evaluations(self, category_assessments: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize evaluation results across categories.

        Args:
            category_assessments: Dictionary of category assessments

        Returns:
            Summary of evaluations
        """
        # Count evaluations by status
        evaluation_counts = {
            "Meets Standard": 0,
            "Needs Improvement": 0,
            "Major Concern": 0,
            "Not Applicable": 0
        }

        # Count by category
        category_counts = {}

        total_items = 0

        for category, assessment in category_assessments.items():
            category_counts[category] = {
                "Meets Standard": 0,
                "Needs Improvement": 0,
                "Major Concern": 0,
                "Not Applicable": 0,
                "total": 0
            }

            for item in assessment.get("items", []):
                evaluation = item.get("evaluation", "Not Evaluated")

                if evaluation in evaluation_counts:
                    evaluation_counts[evaluation] += 1
                    category_counts[category][evaluation] += 1

                category_counts[category]["total"] += 1
                total_items += 1

        # Calculate percentages
        percentages = {}
        for status, count in evaluation_counts.items():
            percentages[status] = (count / total_items * 100) if total_items > 0 else 0

        # Generate category scores (0-100)
        category_scores = {}
        for category, counts in category_counts.items():
            if counts["total"] > 0:
                # Weight: Meets Standard = 100%, Needs Improvement = 50%, Major Concern = 0%, N/A not counted
                weighted_sum = (counts["Meets Standard"] * 100 +
                                counts["Needs Improvement"] * 50)

                applicable_count = counts["total"] - counts["Not Applicable"]

                if applicable_count > 0:
                    category_scores[category] = weighted_sum / applicable_count
                else:
                    category_scores[category] = 0
            else:
                category_scores[category] = 0

        # Calculate overall score
        applicable_count = total_items - evaluation_counts["Not Applicable"]
        overall_score = 0

        if applicable_count > 0:
            weighted_sum = (evaluation_counts["Meets Standard"] * 100 +
                            evaluation_counts["Needs Improvement"] * 50)

            overall_score = weighted_sum / applicable_count

        return {
            "counts": evaluation_counts,
            "percentages": percentages,
            "category_counts": category_counts,
            "category_scores": category_scores,
            "overall_score": overall_score,
            "total_items": total_items
        }

    def _generate_recommendations(self, category_assessments: Dict[str, Dict[str, Any]],
                                  repo_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on assessments.

        Args:
            category_assessments: Dictionary of category assessments
            repo_context: Repository context

        Returns:
            List of prioritized recommendations
        """
        # Collect all items marked as "Major Concern" or "Needs Improvement"
        concerns = []

        for category, assessment in category_assessments.items():
            for item in assessment.get("items", []):
                evaluation = item.get("evaluation", "")

                if evaluation in ["Major Concern", "Needs Improvement"]:
                    concerns.append({
                        "category": category,
                        "criterion": item.get("criterion", ""),
                        "evaluation": evaluation,
                        "evidence": item.get("evidence", ""),
                        "recommendations": item.get("recommendations", ""),
                        "priority": 1 if evaluation == "Major Concern" else 2  # 1 is higher priority
                    })

        # Sort by priority (major concerns first)
        concerns.sort(key=lambda x: x["priority"])

        # If we have more than 10 concerns, create a summary prompt
        if len(concerns) > 10:
            recommendations_prompt = f"""
            Based on the peer review findings, create a prioritized list of the 7-10 most important recommendations 
            to improve the codebase. Focus on items marked as 'Major Concern' and 'Needs Improvement'.

            For each recommendation, provide:
            1. A clear, actionable recommendation title
            2. The category it belongs to
            3. Priority level (High, Medium, Low)
            4. Justification from the evidence
            5. Specific implementation steps

            Issues identified:
            """

            # Add top concerns
            for i, concern in enumerate(concerns[:20]):  # Limit to top 20 for prompt size
                recommendations_prompt += f"""
                {i + 1}. Category: {concern['category']}
                   Issue: {concern['criterion']}
                   Evaluation: {concern['evaluation']}
                   Evidence: {concern['evidence']}
                """

            # Get recommendations from LLM
            recommendations_response = self.model.invoke([
                {"role": "system", "content": recommendations_prompt}
            ])

            # Format recommendations as a list of dictionaries
            return [{
                "title": "Prioritized Recommendations",
                "content": recommendations_response.content
            }]
        else:
            # For fewer concerns, just return them directly
            return [{
                "category": concern["category"],
                "recommendation": concern["recommendations"],
                "evidence": concern["evidence"],
                "priority": "High" if concern["priority"] == 1 else "Medium",
                "criterion": concern["criterion"]
            } for concern in concerns]

    def _generate_peer_review_report(self, review_findings: Dict[str, Any],
                                     repo_context: Dict[str, Any]) -> str:
        """Generate a comprehensive peer review report.

        Args:
            review_findings: Dictionary with review findings
            repo_context: Repository context

        Returns:
            Formatted peer review report
        """
        logging.info("Generating peer review report")
        report = "# Comprehensive Peer Review Report\n\n"

        # Executive Summary
        report += "## 1. Executive Summary\n\n"

        summary_prompt = f"""
        Create a high-level overview (2-3 paragraphs) of the codebase's strengths and areas for improvement 
        based on the peer review findings.

        Overall Score: {review_findings["evaluation_summary"]["overall_score"]:.1f}/100

        Evaluation Summary:
        - Meets Standard: {review_findings["evaluation_summary"]["counts"]["Meets Standard"]} ({review_findings["evaluation_summary"]["percentages"]["Meets Standard"]:.1f}%)
        - Needs Improvement: {review_findings["evaluation_summary"]["counts"]["Needs Improvement"]} ({review_findings["evaluation_summary"]["percentages"]["Needs Improvement"]:.1f}%)
        - Major Concern: {review_findings["evaluation_summary"]["counts"]["Major Concern"]} ({review_findings["evaluation_summary"]["percentages"]["Major Concern"]:.1f}%)
        - Not Applicable: {review_findings["evaluation_summary"]["counts"]["Not Applicable"]} ({review_findings["evaluation_summary"]["percentages"]["Not Applicable"]:.1f}%)

        Keep it concise and objective, highlighting both positives and areas needing attention.
        """

        summary_response = self.model.invoke([{"role": "system", "content": summary_prompt}])
        report += f"{summary_response.content}\n\n"

        # Repository Overview
        report += "## 2. Repository Overview\n\n"

        # Main languages
        report += "### 2.1 Technology Stack\n\n"
        main_languages = repo_context.get("main_languages", [])
        if main_languages:
            report += f"Main languages used in this repository:\n\n"
            for lang in main_languages:
                report += f"- {lang}\n"
        else:
            report += "No main languages identified.\n"

        report += "\n"

        # Directory structure
        report += "### 2.2 Directory Structure\n\n"
        key_directories = repo_context.get("key_directories", [])
        if key_directories:
            report += f"Key directories in the repository:\n\n"
            for directory in key_directories[:10]:  # Limit to top 10
                directory_display = directory if directory else "/"  # Root directory
                files_count = len(repo_context.get("directories", {}).get(directory, []))
                report += f"- `{directory_display}`: {files_count} files\n"
        else:
            report += "No key directories identified.\n"

        report += "\n"

        # Testing
        report += "### 2.3 Testing\n\n"
        test_files = repo_context.get("test_files", [])
        test_directories = repo_context.get("test_directories", [])

        if test_files:
            report += f"Found {len(test_files)} test files"
            if test_directories:
                report += f" in {len(test_directories)} test directories.\n"
            else:
                report += ".\n"
        else:
            report += "No test files identified.\n"

        report += "\n"

        # Quality Assessment Summary
        report += "## 3. Quality Assessment Summary\n\n"

        # Overall score
        report += f"Overall Quality Score: **{review_findings['evaluation_summary']['overall_score']:.1f}/100**\n\n"

        # Category scores
        report += "### 3.1 Scores by Category\n\n"
        report += "| Category | Score | Status |\n"
        report += "|----------|-------|--------|\n"

        category_scores = review_findings["evaluation_summary"]["category_scores"]
        for category, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
            # Determine status based on score
            if score >= 80:
                status = "✓ Good"
            elif score >= 60:
                status = "⚠️ Adequate"
            else:
                status = "❌ Needs Attention"

            report += f"| {category} | {score:.1f} | {status} |\n"

        report += "\n"

        # Evaluation distribution
        report += "### 3.2 Evaluation Distribution\n\n"
        report += "| Status | Count | Percentage |\n"
        report += "|--------|-------|------------|\n"

        counts = review_findings["evaluation_summary"]["counts"]
        percentages = review_findings["evaluation_summary"]["percentages"]

        for status in ["Meets Standard", "Needs Improvement", "Major Concern", "Not Applicable"]:
            report += f"| {status} | {counts[status]} | {percentages[status]:.1f}% |\n"

        report += "\n"

        # Detailed Category Reviews
        report += "## 4. Detailed Category Reviews\n\n"

        category_assessments = review_findings.get("category_assessments", {})
        for category, assessment in category_assessments.items():
            score = review_findings["evaluation_summary"]["category_scores"].get(category, 0)

            report += f"### 4.{list(category_assessments.keys()).index(category) + 1} {category}\n\n"
            report += f"**Score: {score:.1f}/100**\n\n"

            # Add items table
            report += "| Criterion | Evaluation | Recommendations |\n"
            report += "|-----------|------------|------------------|\n"

            for item in assessment.get("items", []):
                criterion = item.get("criterion", "N/A")
                evaluation = item.get("evaluation", "Not Evaluated")
                recommendations = item.get("recommendations", "N/A")

                # Truncate long fields for readability
                if len(recommendations) > 100:
                    recommendations = recommendations[:100] + "..."

                # Escape pipe characters in markdown table
                criterion = criterion.replace("|", "\\|")
                recommendations = recommendations.replace("|", "\\|")

                report += f"| {criterion} | {evaluation} | {recommendations} |\n"

            report += "\n"

            # Add evidence for major concerns and needs improvement
            issues = [item for item in assessment.get("items", [])
                      if item.get("evaluation") in ["Major Concern", "Needs Improvement"]]

            if issues:
                report += "#### Key Issues and Evidence\n\n"

                for item in issues:
                    criterion = item.get("criterion", "N/A")
                    evaluation = item.get("evaluation", "Not Evaluated")
                    evidence = item.get("evidence", "N/A")

                    report += f"**{criterion} ({evaluation})**\n\n"
                    report += f"{evidence}\n\n"

            report += "\n"

        # Priority Recommendations
        report += "## 5. Priority Recommendations\n\n"

        recommendations = review_findings.get("recommendations", [])
        if recommendations:
            if len(recommendations) == 1 and "title" in recommendations[0]:
                # Single comprehensive recommendation set
                report += recommendations[0]["content"]
            else:
                # List of individual recommendations
                for i, rec in enumerate(recommendations):
                    priority = rec.get("priority", "Medium")
                    category = rec.get("category", "General")
                    criterion = rec.get("criterion", "")
                    recommendation = rec.get("recommendation", "")

                    report += f"### 5.{i + 1} {criterion}\n\n"
                    report += f"**Priority: {priority} | Category: {category}**\n\n"
                    report += f"{recommendation}\n\n"
        else:
            report += "No priority recommendations identified.\n\n"

        # Best Practices by Language
        # Mitigation Plans
        report += "## 6. Mitigation Plans\n\n"

        # Group findings by category
        category_issues = {}

        for category, assessment in category_assessments.items():
            issues = [item for item in assessment.get("items", [])
                      if item.get("evaluation") in ["Major Concern", "Needs Improvement"]]

            if issues:
                category_issues[category] = issues

        # Determine top categories with issues
        top_categories = sorted(
            category_issues.keys(),
            key=lambda c: len(category_issues[c]),
            reverse=True
        )

        if not top_categories:
            report += "No significant issues requiring mitigation were identified.\n\n"
        else:
            for i, category in enumerate(top_categories):
                issues = category_issues[category]
                report += f"### 6.{i + 1} {category} Mitigation Plan\n\n"

                # Create a consolidated list of issues for this category
                issues_summary = "\n".join([
                    f"- {item.get('criterion')}: {item.get('evaluation')}"
                    for item in issues
                ])

                mitigation_prompt = f"""
                Create a detailed mitigation plan for issues identified in the '{category}' category. 
                Here are the specific issues identified:

                {issues_summary}

                Your plan should include:
                1. Prioritized steps to address these issues
                2. Specific actionable recommendations
                3. Potential tools or techniques to help implement solutions
                4. Timeline considerations (quick wins vs. longer-term solutions)
                5. Success criteria to measure improvement

                Format as a detailed markdown plan with clear sections.
                """

                mitigation_response = self.model.invoke([
                    {"role": "system", "content": mitigation_prompt}
                ])

                report += f"{mitigation_response.content}\n\n"

        # Conclusion
        report += "## 7. Conclusion\n\n"

        conclusion_prompt = f"""
        Write a brief conclusion (1-2 paragraphs) for this peer review report.
        Summarize the overall quality, key areas for improvement, and next steps.

        Overall Score: {review_findings["evaluation_summary"]}
        """

        conclusion_response = self.model.invoke([
            {"role": "system", "content": conclusion_prompt}
        ])

        report += f"{conclusion_response.content}\n\n"

        # Add timestamp
        from datetime import datetime
        report += f"\n\n---\n\nPeer Review completed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        return report