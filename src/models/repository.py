"""
Repository data models.

This module provides data models for representing repositories
and their components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class FileInfo:
    """Information about a file in the repository."""

    path: str
    name: str
    extension: str
    size: int
    is_binary: bool = False
    type: str = "unknown"
    description: str = ""

    @property
    def relative_path(self) -> str:
        """Get the path relative to the repository root.

        Returns:
            Relative file path
        """
        # This is a simplification and assumes path is already relative
        # A more robust implementation would use the repository path
        return self.path

    @property
    def language(self) -> str:
        """Get the programming language of the file based on extension.

        Returns:
            Programming language name
        """
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
            ".swift": "Swift",
            ".kt": "Kotlin",
            ".rs": "Rust",
            ".scala": "Scala",
            ".html": "HTML",
            ".css": "CSS",
            ".scss": "SCSS",
            ".less": "LESS",
            ".json": "JSON",
            ".xml": "XML",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".md": "Markdown",
            ".sql": "SQL"
        }

        return ext_to_language.get(self.extension.lower(), "Unknown")


@dataclass
class DirectoryInfo:
    """Information about a directory in the repository."""

    path: str
    name: str
    files: List[FileInfo] = field(default_factory=list)
    subdirectories: List["DirectoryInfo"] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        """Get the total number of files in this directory and subdirectories.

        Returns:
            Total file count
        """
        count = len(self.files)
        for subdir in self.subdirectories:
            count += subdir.file_count
        return count

    def get_files_by_type(self, file_type: str) -> List[FileInfo]:
        """Get all files of a specific type.

        Args:
            file_type: Type of files to retrieve

        Returns:
            List of matching files
        """
        matching_files = [f for f in self.files if f.type == file_type]

        for subdir in self.subdirectories:
            matching_files.extend(subdir.get_files_by_type(file_type))

        return matching_files

    def get_files_by_extension(self, extension: str) -> List[FileInfo]:
        """Get all files with a specific extension.

        Args:
            extension: File extension (with or without dot)

        Returns:
            List of matching files
        """
        if not extension.startswith("."):
            extension = f".{extension}"

        matching_files = [f for f in self.files if f.extension.lower() == extension.lower()]

        for subdir in self.subdirectories:
            matching_files.extend(subdir.get_files_by_extension(extension))

        return matching_files


@dataclass
class Repository:
    """Repository information and structure."""

    path: str
    name: str
    root_directory: DirectoryInfo = field(default_factory=lambda: DirectoryInfo("", ""))
    file_count: int = 0
    all_files: Dict[str, FileInfo] = field(default_factory=dict)
    analyzed_files: Set[str] = field(default_factory=set)

    def add_file(self, file_info: FileInfo) -> None:
        """Add a file to the repository.

        Args:
            file_info: Information about the file
        """
        self.all_files[file_info.path] = file_info
        self.file_count += 1

    def get_file(self, file_path: str) -> Optional[FileInfo]:
        """Get a file by path.

        Args:
            file_path: Path to the file

        Returns:
            File information, or None if not found
        """
        return self.all_files.get(file_path)

    def mark_file_analyzed(self, file_path: str) -> None:
        """Mark a file as analyzed.

        Args:
            file_path: Path to the file
        """
        self.analyzed_files.add(file_path)

    def is_file_analyzed(self, file_path: str) -> bool:
        """Check if a file has been analyzed.

        Args:
            file_path: Path to the file

        Returns:
            True if the file has been analyzed, False otherwise
        """
        return file_path in self.analyzed_files

    @property
    def analyzed_file_count(self) -> int:
        """Get the number of analyzed files.

        Returns:
            Number of analyzed files
        """
        return len(self.analyzed_files)

    @property
    def analysis_progress(self) -> float:
        """Get the analysis progress as a percentage.

        Returns:
            Percentage of files analyzed
        """
        if self.file_count == 0:
            return 0.0
        return (self.analyzed_file_count / self.file_count) * 100

    def get_files_by_language(self, language: str) -> List[FileInfo]:
        """Get all files in a specific programming language.

        Args:
            language: Programming language name

        Returns:
            List of matching files
        """
        return [f for f in self.all_files.values() if f.language.lower() == language.lower()]

    def get_file_extensions(self) -> Dict[str, int]:
        """Get all file extensions and their counts.

        Returns:
            Dictionary mapping extensions to counts
        """
        extensions = {}
        for file_info in self.all_files.values():
            if file_info.extension:
                extensions[file_info.extension] = extensions.get(file_info.extension, 0) + 1
        return extensions

    def get_languages(self) -> Dict[str, int]:
        """Get all programming languages and their file counts.

        Returns:
            Dictionary mapping languages to file counts
        """
        languages = {}
        for file_info in self.all_files.values():
            if file_info.language != "Unknown":
                languages[file_info.language] = languages.get(file_info.language, 0) + 1
        return languages