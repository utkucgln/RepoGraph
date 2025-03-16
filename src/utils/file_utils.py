"""
File utilities for repository analysis.

This module provides functions for working with files and directories
in the context of repository analysis.
"""

import os
import logging
import shutil
from pathlib import Path
from typing import List, Optional, Set, Tuple

logger = logging.getLogger("utils.file")

def get_all_files(repo_path: str, ignore_gitignore: bool = True,
                 ignore_dot_dirs: bool = True) -> List[str]:
    """Get all files in a repository.

    Args:
        repo_path: Path to the repository
        ignore_gitignore: Whether to respect .gitignore rules
        ignore_dot_dirs: Whether to ignore directories starting with a dot

    Returns:
        List of file paths
    """
    logger.info(f"Scanning repository at: {repo_path}")

    ignore_patterns = None
    if ignore_gitignore:
        ignore_patterns = _load_gitignore_patterns(repo_path)

    all_files = []
    for root, dirs, files in os.walk(repo_path):
        # Skip directories starting with a dot if requested
        if ignore_dot_dirs:
            dirs[:] = [d for d in dirs if not d.startswith('.')]

        rel_root = os.path.relpath(root, repo_path)

        for file in files:
            filepath = os.path.join(root, file)
            rel_filepath = os.path.join(rel_root, file) if rel_root != '.' else file

            # Skip files matching gitignore patterns
            if ignore_patterns and _should_ignore(rel_filepath, ignore_patterns):
                logger.debug(f"Ignoring {rel_filepath} due to .gitignore")
                continue

            all_files.append(filepath)

    logger.info(f"Total files found: {len(all_files)}")
    return all_files

def _load_gitignore_patterns(repo_path: str) -> Optional[Set[str]]:
    """Load patterns from .gitignore file.

    Args:
        repo_path: Path to the repository

    Returns:
        Set of gitignore patterns, or None if .gitignore not found
    """
    gitignore_path = os.path.join(repo_path, '.gitignore')
    if not os.path.exists(gitignore_path):
        logger.info("No .gitignore file found.")
        return None

    try:
        from pathspec import PathSpec
        from pathspec.patterns.gitwildmatch import GitWildMatchPattern

        with open(gitignore_path, 'r') as f:
            ignore_patterns = f.read().splitlines()

        # Filter out comments and empty lines
        ignore_patterns = [p for p in ignore_patterns if p and not p.startswith('#')]

        logger.info(f"Loaded {len(ignore_patterns)} patterns from .gitignore")
        return PathSpec.from_lines(GitWildMatchPattern, ignore_patterns)

    except ImportError:
        logger.warning("pathspec module not installed. Gitignore processing disabled.")
        return None

def _should_ignore(filepath: str, patterns) -> bool:
    """Check if a file should be ignored based on gitignore patterns.

    Args:
        filepath: Relative path of the file
        patterns: PathSpec object with gitignore patterns

    Returns:
        True if the file should be ignored, False otherwise
    """
    return patterns.match_file(filepath)

def get_file_type(filepath: str) -> str:
    """Get the type of a file based on its extension.

    Args:
        filepath: Path to the file

    Returns:
        File type based on extension
    """
    ext = Path(filepath).suffix.lower()

    # Map extensions to file types
    extension_map = {
        # Programming languages
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'jsx',
        '.tsx': 'tsx',
        '.java': 'java',
        '.rb': 'ruby',
        '.php': 'php',
        '.go': 'go',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c-header',
        '.hpp': 'cpp-header',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.rs': 'rust',
        '.scala': 'scala',

        # Web
        '.html': 'html',
        '.htm': 'html',
        '.css': 'css',
        '.scss': 'scss',
        '.sass': 'sass',
        '.less': 'less',

        # Data
        '.json': 'json',
        '.xml': 'xml',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.csv': 'csv',
        '.tsv': 'tsv',
        '.sql': 'sql',
        '.db': 'binary',

        # Configuration
        '.ini': 'ini',
        '.cfg': 'config',
        '.conf': 'config',
        '.properties': 'properties',
        '.toml': 'toml',
        '.env': 'env',

        # Documentation
        '.md': 'markdown',
        '.markdown': 'markdown',
        '.rst': 'rst',
        '.txt': 'text',
        '.pdf': 'binary',
        '.doc': 'binary',
        '.docx': 'binary',

        # Images
        '.jpg': 'binary',
        '.jpeg': 'binary',
        '.png': 'binary',
        '.gif': 'binary',
        '.svg': 'svg',

        # Other
        '.gitignore': 'gitignore',
        '.dockerignore': 'dockerignore',
        'Dockerfile': 'dockerfile',
        '.travis.yml': 'yaml',
        '.gitlab-ci.yml': 'yaml',
        'Makefile': 'makefile',
    }

    return extension_map.get(ext, 'unknown')

def read_file(filepath: str, max_size: int = 10 * 1024 * 1024) -> Optional[str]:
    """Read a file with safeguards for large files.

    Args:
        filepath: Path to the file to read
        max_size: Maximum file size to read (defaults to 10MB)

    Returns:
        File content as string, or None if the file couldn't be read
    """
    try:
        # Check file size first
        file_size = os.path.getsize(filepath)
        if file_size > max_size:
            logger.warning(f"File {filepath} is too large ({file_size} bytes). Skipping.")
            return None

        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252']
        content = None

        for encoding in encodings:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            # If all text encodings fail, this might be a binary file
            logger.warning(f"Could not decode {filepath} as text. It might be a binary file.")
            return None

        return content

    except Exception as e:
        logger.error(f"Error reading file {filepath}: {str(e)}")
        return None

def is_binary_file(filepath: str) -> bool:
    """Check if a file is binary (non-text).

    Args:
        filepath: Path to the file

    Returns:
        True if the file is likely binary, False otherwise
    """
    # Check by extension first
    ext = Path(filepath).suffix.lower()
    binary_extensions = {'.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png',
                         '.gif', '.zip', '.tar', '.gz', '.rar', '.exe',
                         '.dll', '.so', '.pyc', '.class', '.o'}

    if ext in binary_extensions:
        return True

    # If extension check isn't conclusive, try reading the file
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            # Look for null bytes which are rare in text files
            if b'\x00' in chunk:
                return True
            # Count ASCII vs non-ASCII characters
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F)))
            return bool(chunk.translate(None, text_chars))
    except Exception:
        # If we can't read the file, assume it's not binary
        return False

def count_files_by_type(repo_path: str) -> dict:
    """Count files by type in a repository.

    Args:
        repo_path: Path to the repository

    Returns:
        Dictionary mapping file types to counts
    """
    files = get_all_files(repo_path)

    counts = {}
    for filepath in files:
        file_type = get_file_type(filepath)
        counts[file_type] = counts.get(file_type, 0) + 1

    return counts

def find_files_by_pattern(repo_path: str, pattern: str) -> List[str]:
    """Find files matching a pattern in a repository.

    Args:
        repo_path: Path to the repository
        pattern: Glob pattern to match files against

    Returns:
        List of matching file paths
    """
    from glob import glob

    # Construct the pattern path
    pattern_path = os.path.join(repo_path, pattern)

    # Find matching files
    matching_files = glob(pattern_path, recursive=True)

    return matching_files

def get_file_info(filepath: str) -> dict:
    """Get detailed information about a file.

    Args:
        filepath: Path to the file

    Returns:
        Dictionary with file information
    """
    stats = os.stat(filepath)

    return {
        'path': filepath,
        'name': os.path.basename(filepath),
        'size': stats.st_size,
        'type': get_file_type(filepath),
        'modified': stats.st_mtime,
        'is_binary': is_binary_file(filepath)
    }

def get_project_structure(repo_path: str) -> dict:
    """Get a nested dictionary representing the project structure.

    Args:
        repo_path: Path to the repository

    Returns:
        Nested dictionary representing the project structure
    """
    structure = {}

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        # Calculate path relative to repo root
        rel_path = os.path.relpath(root, repo_path)
        if rel_path == '.':
            # Files in root directory
            structure['files'] = [f for f in files if not f.startswith('.')]
            structure['dirs'] = {}
        else:
            # Traverse into the nested structure
            parts = rel_path.split(os.sep)
            current = structure
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    # Last part, add files
                    current['dirs'][part] = {
                        'files': [f for f in files if not f.startswith('.')],
                        'dirs': {}
                    }
                else:
                    # Navigate deeper
                    current = current['dirs'].get(part, {'files': [], 'dirs': {}})

    return structure