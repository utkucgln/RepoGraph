"""
Report generator agent.

This module provides an agent that generates comprehensive reports
about repository structure, functionality, and architecture.
"""

import os
import logging
import re
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from src.core.agent_base import Agent
from src.utils.logging_utils import log_execution_time
from src.models.report import RepositoryReport, ReportSection, MetricValue, TableData
from src.models.repository import Repository


class ReportGeneratorAgent(Agent):
    """Agent for generating comprehensive repository reports.

    This agent analyzes file descriptions and repository structure
    to generate a detailed report about the repository.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the report generator agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and generate a repository report.

        Args:
            state: Current state containing file descriptions

        Returns:
            Updated state with comprehensive report
        """
        self.log_info("Report Generator Agent: Starting report generation")

        # Check if file descriptions are available
        file_descriptions = self._get_file_descriptions(state)
        if not file_descriptions:
            self.log_error("Report Generator Agent: No file descriptions found in state")
            error_msg = "No file descriptions found. File analyzer must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get repository path and other context
        repo_path = self._extract_repo_path(state)
        repository = state.get("repository")
        repository_name = os.path.basename(os.path.abspath(repo_path)) if repo_path else "Unknown Repository"

        # Extract repository structure and context
        repo_context = self._extract_repository_context(state, repository)

        # Generate the comprehensive report
        report_content = self._generate_report(file_descriptions, repo_context, repository_name)

        # Create a report object
        report_obj = self._create_report_object(report_content, repo_path, repository_name, repository)

        # Add report to state
        state = self.add_message_to_state(state, report_content, "system", "report")

        # Add report object to state
        state["report"] = report_obj

        # Save report to file if output directory exists
        output_dir = "reports"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_path = os.path.join(output_dir, f"developer_guide_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        self.log_info(f"Report saved to {report_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Report Generator Agent: Report generation complete")
        return state

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

    def _extract_repository_context(self, state: Dict[str, Any],
                                    repository: Optional[Repository] = None) -> Dict[str, Any]:
        """Extract repository context for report generation.

        Args:
            state: Current state
            repository: Optional repository object

        Returns:
            Dictionary with repository context information
        """
        context = {}

        # Get repository stats if available
        repo_stats_message = self.get_last_message_by_name(state, "repository_stats")
        if repo_stats_message:
            content = repo_stats_message.get("content", "")
            if "Repository Statistics:" in content:
                try:
                    # Try to parse the statistics
                    stats_str = content.split("Repository Statistics:")[1].strip()
                    # Simple approach to extract dict-like content
                    stats_str = stats_str.replace("'", "\"")

                    # Extract the data using regex
                    file_count_match = re.search(r'"total_files":\s*(\d+)', stats_str)
                    if file_count_match:
                        context["total_files"] = int(file_count_match.group(1))

                    # Extract extensions
                    extensions_match = re.search(r'"by_extension":\s*{([^}]+)}', stats_str)
                    if extensions_match:
                        extensions_str = extensions_match.group(1)
                        extensions = {}
                        for pair in re.finditer(r'"([^"]+)":\s*(\d+)', extensions_str):
                            extensions[pair.group(1)] = int(pair.group(2))
                        context["extensions"] = extensions

                    # Extract languages
                    languages_match = re.search(r'"by_language":\s*{([^}]+)}', stats_str)
                    if languages_match:
                        languages_str = languages_match.group(1)
                        languages = {}
                        for pair in re.finditer(r'"([^"]+)":\s*(\d+)', languages_str):
                            languages[pair.group(1)] = int(pair.group(2))
                        context["languages"] = languages

                except Exception as e:
                    self.log_warning(f"Error parsing repository statistics: {str(e)}")

        # Get additional context from repository object
        if repository:
            if not "total_files" in context:
                context["total_files"] = repository.file_count

            if not "extensions" in context:
                context["extensions"] = repository.get_file_extensions()

            if not "languages" in context:
                context["languages"] = repository.get_languages()

        # Try to identify key project files
        key_project_files = {
            "README.md": "Documentation",
            "package.json": "Node.js dependencies",
            "requirements.txt": "Python dependencies",
            "go.mod": "Go dependencies",
            "pom.xml": "Java Maven dependencies",
            "build.gradle": "Java Gradle dependencies",
            "Gemfile": "Ruby dependencies",
            "composer.json": "PHP dependencies",
            ".gitignore": "Git ignored files",
            "Dockerfile": "Docker configuration",
            "docker-compose.yml": "Docker Compose configuration",
            "Makefile": "Build configuration"
        }

        found_project_files = {}
        for file_path in state.get("file_list", []):
            file_name = os.path.basename(file_path)
            if file_name in key_project_files:
                found_project_files[file_name] = key_project_files[file_name]

        context["key_files"] = found_project_files

        # Identify likely technology stack
        tech_stack = []

        # Check extensions
        extensions = context.get("extensions", {})
        if ".py" in extensions and extensions[".py"] > 0:
            tech_stack.append("Python")
        if ".js" in extensions and extensions[".js"] > 0:
            tech_stack.append("JavaScript")
        if ".ts" in extensions and extensions[".ts"] > 0:
            tech_stack.append("TypeScript")
        if ".java" in extensions and extensions[".java"] > 0:
            tech_stack.append("Java")
        if ".go" in extensions and extensions[".go"] > 0:
            tech_stack.append("Go")
        if ".rb" in extensions and extensions[".rb"] > 0:
            tech_stack.append("Ruby")
        if ".php" in extensions and extensions[".php"] > 0:
            tech_stack.append("PHP")

        # Check key files for frameworks
        if "package.json" in found_project_files:
            tech_stack.append("Node.js")
        if "requirements.txt" in found_project_files:
            # Could be Django, Flask, FastAPI, etc.
            pass

        context["tech_stack"] = tech_stack

        return context

    def _generate_report(self, file_descriptions: str,
                         repo_context: Dict[str, Any],
                         repository_name: str) -> str:
        """Generate a comprehensive repository report.

        Args:
            file_descriptions: File descriptions text
            repo_context: Repository context information
            repository_name: Name of the repository

        Returns:
            Comprehensive report content
        """
        self.log_info("Generating comprehensive repository report")

        # Create context information for the LLM
        context_info = ""

        # Add technology stack
        if repo_context.get("tech_stack"):
            context_info += f"Technology Stack: {', '.join(repo_context['tech_stack'])}\n\n"

        # Add file statistics
        context_info += f"Total Files: {repo_context.get('total_files', 'Unknown')}\n\n"

        # Add top file extensions
        if repo_context.get("extensions"):
            context_info += "Top File Extensions:\n"
            for ext, count in sorted(repo_context["extensions"].items(), key=lambda x: x[1], reverse=True)[:5]:
                context_info += f"- {ext}: {count} files\n"
            context_info += "\n"

        # Add key project files
        if repo_context.get("key_files"):
            context_info += "Key Project Files:\n"
            for file_name, description in repo_context["key_files"].items():
                context_info += f"- {file_name}: {description}\n"
            context_info += "\n"

        # Create the prompt for the report
        prompt = f"""
        You are tasked with creating a comprehensive developer guide for the '{repository_name}' software repository. 
        This will be the primary documentation for new developers joining the project. 
        Based on file-level analyses, produce a detailed, well-structured report that presents 
        a holistic view of the repository's architecture, functionality, and best practices.

        Repository Context Information:
        {context_info}

        Your report should be comprehensive, practical, and actionable. Rather than simply listing files, 
        synthesize the underlying architecture, patterns, and developer workflows. Include concrete 
        examples, code snippets, and practical advice wherever possible.

        Structure your report with these major sections (and add subsections as appropriate):

        # {repository_name} Developer Guide

        ## 1. Executive Summary
        Provide a concise overview of the repository's purpose, core functionality, and key technologies. 
        This should give developers a quick understanding of what this software does and its technical foundation.

        ## 2. Architecture Overview
        ### 2.1 System Architecture
        Describe the high-level architecture, major components, and how they interact. Include a text description 
        of what a diagram would show if applicable.
        ### 2.2 Design Patterns
        Identify and explain key design patterns used in the codebase.
        ### 2.3 Data Flow
        Explain how data flows through the system, from inputs to outputs.

        ## 3. Core Components
        For each major component or module:
        - Purpose and responsibilities
        - Key classes/functions
        - Usage examples
        - Interactions with other components

        ## 4. Developer Workflows
        ### 4.1 Setup and Installation
        Detailed steps for setting up a development environment.
        ### 4.2 Build and Test
        How to build, test, and validate changes.
        ### 4.3 Common Development Tasks
        Examples of frequent tasks developers will perform (with code examples).

        ## 5. API Reference
        Summary of key APIs, their purpose, and usage examples.

        ## 6. Best Practices and Conventions
        Coding standards, naming conventions, and design principles to follow.

        ## 7. Troubleshooting and FAQs
        Common issues and their solutions.

        ## 8. Glossary
        Definitions of domain-specific terms and acronyms.

        Based on the following file-level descriptions, create this comprehensive developer guide:

        {file_descriptions}

        Make the guide practical, thorough, and accessible to new developers. Focus on helping them understand how to effectively 
        work with this codebase rather than just describing what exists. Use a clear, direct writing style with concrete examples.

        Output the complete report in clean, well-formatted Markdown.
        """

        # Generate the report using LLM
        self.log_info("Invoking LLM for report generation")
        response = self.model.invoke([{"role": "system", "content": prompt}])
        report = response.content

        # Add a timestamp to the report
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report += f"\n\n---\n\n*Report generated: {timestamp}*"

        return report

    def _create_report_object(self, report_content: str, repo_path: str,
                              repository_name: str,
                              repository: Optional[Repository] = None) -> RepositoryReport:
        """Create a structured report object from the report content.

        Args:
            report_content: Generated report content
            repo_path: Repository path
            repository_name: Repository name
            repository: Optional repository object

        Returns:
            RepositoryReport object
        """
        # Create a new report object
        report = RepositoryReport(
            repository_path=repo_path,
            repository_name=repository_name
        )

        # Extract sections from the report content
        sections = self._extract_sections(report_content)

        # Add sections to the report
        for i, (title, content) in enumerate(sections):
            section = ReportSection(
                title=title,
                content=content,
                order=i
            )
            report.add_section(section)

        # Add metrics if repository object is available
        if repository:
            report.add_metric(MetricValue(
                name="Total Files",
                value=repository.file_count,
                description="Total number of files in the repository"
            ))

            report.add_metric(MetricValue(
                name="Analyzed Files",
                value=repository.analyzed_file_count,
                description="Number of files analyzed",
                unit="files"
            ))

            # Add file type distribution
            extensions = repository.get_file_extensions()
            if extensions:
                headers = ["Extension", "Count"]
                rows = [[ext, count] for ext, count in
                        sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10]]

                report.add_table("File Extension Distribution", TableData(
                    headers=headers,
                    rows=rows,
                    caption="Top 10 file extensions by count"
                ))

        return report

    def _extract_sections(self, report_content: str) -> List[Tuple[str, str]]:
        """Extract titled sections from the report content.

        Args:
            report_content: Report content

        Returns:
            List of (title, content) tuples
        """
        # Split by headings
        sections = []
        lines = report_content.split('\n')

        current_title = None
        current_content = []

        for line in lines:
            # Check for headings (## Title)
            if line.startswith('## '):
                # Save the previous section if it exists
                if current_title:
                    sections.append((current_title, '\n'.join(current_content)))

                # Start a new section
                current_title = line[3:].strip()
                current_content = []
            elif current_title:
                # Add content to the current section
                current_content.append(line)

        # Add the last section
        if current_title:
            sections.append((current_title, '\n'.join(current_content)))

        return sections