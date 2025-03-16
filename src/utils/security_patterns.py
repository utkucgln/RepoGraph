"""
Security patterns for code analysis.

This module provides security patterns and vulnerability detection
rules for identifying potential security issues in code.
"""

from typing import Dict, List, Pattern
import re

# Regular expression patterns for security vulnerability detection
SECURITY_PATTERNS = {
    "Authentication": {
        "description": "Authentication mechanisms and vulnerabilities",
        "patterns": [
            r"(?<![a-zA-Z0-9_])auth[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])login[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])sign[_]?in[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])validate[_]?credentials[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])check[_]?password[a-zA-Z_]*\s*\("
        ],
        "severity": "high"
    },
    "Authorization": {
        "description": "Authorization controls and access checks",
        "patterns": [
            r"(?<![a-zA-Z0-9_])authorize[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])has[_]?permission[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])is[_]?admin[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])check[_]?access[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])validate[_]?token[a-zA-Z_]*\s*\("
        ],
        "severity": "high"
    },
    "InputValidation": {
        "description": "Input validation and sanitization",
        "patterns": [
            r"(?<![a-zA-Z0-9_])validate[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])sanitize[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])clean[_]?input[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])escape[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])filter[_]?input[a-zA-Z_]*\s*\("
        ],
        "severity": "medium"
    },
    "DataStorage": {
        "description": "Sensitive data storage and handling",
        "patterns": [
            r"(?<![a-zA-Z0-9_])encrypt[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])decrypt[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])hash[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])store[_]?password[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])save[_]?credentials[a-zA-Z_]*\s*\("
        ],
        "severity": "high"
    },
    "SessionManagement": {
        "description": "Session creation, validation, and management",
        "patterns": [
            r"(?<![a-zA-Z0-9_])create[_]?session[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])validate[_]?session[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])destroy[_]?session[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])generate[_]?token[a-zA-Z_]*\s*\(",
            r"(?<![a-zA-Z0-9_])expire[_]?session[a-zA-Z_]*\s*\("
        ],
        "severity": "high"
    },
    "SQLInjection": {
        "description": "Potential SQL injection vulnerabilities",
        "patterns": [
            r"execute\([\"'][^\"']*\s*\+",
            r"cursor\.execute\([^,]*\+",
            r"\.execute\(\s*f[\"\']",
            r"\.query\([^,]*\+",
            r"\.raw\(",
            r"(?<![a-zA-Z0-9_])raw_input",
            r".*\s+LIKE\s+[\'\"]%\s*\+.*",
            r".*\s+LIKE\s+[\'\"]%.*\+\s*[\'\"]%.*"
        ],
        "severity": "critical"
    },
    "CommandInjection": {
        "description": "Potential command injection vulnerabilities",
        "patterns": [
            r"(?<![a-zA-Z0-9_])system\s*\(",
            r"(?<![a-zA-Z0-9_])subprocess\.call",
            r"(?<![a-zA-Z0-9_])subprocess\.Popen",
            r"(?<![a-zA-Z0-9_])os\.system",
            r"(?<![a-zA-Z0-9_])exec\s*\(",
            r"(?<![a-zA-Z0-9_])eval\s*\(",
            r"(?<![a-zA-Z0-9_])popen\s*\("
        ],
        "severity": "critical"
    },
    "CrossSiteScripting": {
        "description": "Potential XSS vulnerabilities",
        "patterns": [
            r"\.innerHTML\s*=",
            r"\.html\([^)]*\$",
            r"(?<![a-zA-Z0-9_])document\.write",
            r"render_template\([^)]*\+",
            r"\.render\([^)]*\)",
            r"\.add\([^)]*\+",
            r"\.append\([^)]*\+"
        ],
        "severity": "high"
    },
    "InsecureConfiguration": {
        "description": "Insecure configuration settings",
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\\*['\"]",
            r"set_timeout\([^)]*0\)",
            r"(?<![a-zA-Z0-9_])ssl_verify\s*=\s*False",
            r"(?<![a-zA-Z0-9_])verify\s*=\s*False",
            r"(?<![a-zA-Z0-9_])secure\s*=\s*False",
            r"CSRF_PROTECTION\s*=\s*False"
        ],
        "severity": "medium"
    },
    "InsecureCryptography": {
        "description": "Weak or insecure cryptographic practices",
        "patterns": [
            r"(?<![a-zA-Z0-9_])md5\s*\(",
            r"(?<![a-zA-Z0-9_])sha1\s*\(",
            r"(?<![a-zA-Z0-9_])random\s*\(",
            r"(?<![a-zA-Z0-9_])DES\.",
            r"(?<![a-zA-Z0-9_])RC4\.",
            r"generate_random",
            r"(?<![a-zA-Z0-9_])crypt"
        ],
        "severity": "high"
    },
    "InsecureFileOperations": {
        "description": "Insecure file operations and uploads",
        "patterns": [
            r"open\([^,)]*\+",
            r"file_get_contents\([^)]*\$",
            r"(?<![a-zA-Z0-9_])upload[a-zA-Z_]*\(",
            r"(?<![a-zA-Z0-9_])download[a-zA-Z_]*\(",
            r"(?<![a-zA-Z0-9_])read_file",
            r"(?<![a-zA-Z0-9_])write_file"
        ],
        "severity": "medium"
    },
    "InsecureDeserialization": {
        "description": "Insecure deserialization practices",
        "patterns": [
            r"(?<![a-zA-Z0-9_])pickle\.load",
            r"(?<![a-zA-Z0-9_])yaml\.load\([^)]*Loader=yaml\.Loader",
            r"(?<![a-zA-Z0-9_])marshal\.load",
            r"(?<![a-zA-Z0-9_])unserialize\(",
            r"(?<![a-zA-Z0-9_])json\.loads",
            r"ObjectInputStream"
        ],
        "severity": "high"
    },
    "ErrorHandling": {
        "description": "Improper error handling and logging",
        "patterns": [
            r"catch\s*\([^)]*\)\s*\{\s*\}",
            r"except:(\s*pass|\s*$)",
            r"\.printStackTrace\(\)",
            r"console\.log\([^)]*error",
            r"print\(\s*['\"]error",
            r"logging\.[a-z]+\([^)]*exception"
        ],
        "severity": "low"
    },
    "HardcodedSecrets": {
        "description": "Hardcoded credentials and secrets",
        "patterns": [
            r"(?<![a-zA-Z0-9_])password\s*=\s*['\"][^'\"]+['\"]",
            r"(?<![a-zA-Z0-9_])secret\s*=\s*['\"][^'\"]+['\"]",
            r"(?<![a-zA-Z0-9_])api[_]?key\s*=\s*['\"][^'\"]+['\"]",
            r"(?<![a-zA-Z0-9_])token\s*=\s*['\"][^'\"]+['\"]",
            r"(?<![a-zA-Z0-9_])auth[_]?token\s*=\s*['\"][^'\"]+['\"]"
        ],
        "severity": "critical"
    }
}

# Compiled patterns for more efficient matching
COMPILED_PATTERNS = {}

def compile_patterns():
    """Compile regex patterns for performance."""
    for category, info in SECURITY_PATTERNS.items():
        COMPILED_PATTERNS[category] = [re.compile(pattern) for pattern in info["patterns"]]

# Compile patterns at module import time
compile_patterns()

def check_security_pattern(content: str, pattern: Pattern) -> List[int]:
    """Check a security pattern against file content.

    Args:
        content: File content as string
        pattern: Compiled regular expression pattern

    Returns:
        List of line numbers where the pattern was found
    """
    matches = pattern.finditer(content)
    line_numbers = []

    for match in matches:
        # Get line number for the match
        line_number = content[:match.start()].count('\n') + 1
        line_numbers.append(line_number)

    return line_numbers

def scan_content_for_security_issues(content: str) -> Dict[str, List[Dict]]:
    """Scan content for potential security issues.

    Args:
        content: File content as string

    Returns:
        Dictionary mapping categories to lists of findings
    """
    findings = {}

    for category, patterns in COMPILED_PATTERNS.items():
        category_findings = []
        severity = SECURITY_PATTERNS[category]["severity"]

        for i, pattern in enumerate(patterns):
            line_numbers = check_security_pattern(content, pattern)
            if line_numbers:
                category_findings.append({
                    "pattern_index": i,
                    "pattern": SECURITY_PATTERNS[category]["patterns"][i],
                    "line_numbers": line_numbers,
                    "severity": severity
                })

        if category_findings:
            findings[category] = category_findings

    return findings

def get_line_context(content: str, line_number: int, context_lines: int = 2) -> str:
    """Get the context around a specific line.

    Args:
        content: File content as string
        line_number: Line number to get context for (1-based)
        context_lines: Number of lines before and after for context

    Returns:
        String with the line and its context
    """
    lines = content.split('\n')
    if line_number < 1 or line_number > len(lines):
        return ""

    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)

    context = []
    for i in range(start, end):
        prefix = ">" if i == line_number - 1 else " "
        context.append(f"{prefix} {i+1}: {lines[i]}")

    return '\n'.join(context)

def get_security_categories() -> List[Dict]:
    """Get all security categories with descriptions.

    Returns:
        List of dictionaries with category information
    """
    return [
        {
            "name": category,
            "description": info["description"],
            "severity": info["severity"],
            "pattern_count": len(info["patterns"])
        }
        for category, info in SECURITY_PATTERNS.items()
    ]

def get_severity_level(severity: str) -> int:
    """Convert severity string to numeric level.

    Args:
        severity: Severity string (critical, high, medium, low)

    Returns:
        Numeric severity level (4=critical, 3=high, 2=medium, 1=low)
    """
    severity_map = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }
    return severity_map.get(severity.lower(), 0)