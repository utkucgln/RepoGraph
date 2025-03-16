"""
Findings data models.

This module provides data models for representing analysis findings,
issues, and recommendations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from datetime import datetime


class SeverityLevel(Enum):
    """Severity levels for issues and findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric_value(self) -> int:
        """Get numeric value of severity level for sorting.

        Returns:
            Numeric severity value (5=critical, 1=info)
        """
        values = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        return values.get(self.value, 0)

    @classmethod
    def from_string(cls, severity: str) -> "SeverityLevel":
        """Create a severity level from a string.

        Args:
            severity: String representation of severity

        Returns:
            SeverityLevel enum value

        Raises:
            ValueError: If the string is not a valid severity level
        """
        severity = severity.lower()
        for level in cls:
            if level.value == severity:
                return level

        # Default to INFO for unknown severity
        return cls.INFO


@dataclass
class CodeLocation:
    """Location in code for a finding."""

    file_path: str
    line_number: int
    column: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None

    @property
    def location_str(self) -> str:
        """Get a string representation of the location.

        Returns:
            Location string
        """
        location = f"{self.file_path}:{self.line_number}"
        if self.column is not None:
            location += f":{self.column}"
        if self.class_name and self.method_name:
            location += f" ({self.class_name}.{self.method_name})"
        elif self.method_name:
            location += f" ({self.method_name})"
        elif self.class_name:
            location += f" ({self.class_name})"
        return location


@dataclass
class CodeSnippet:
    """Code snippet for a finding."""

    code: str
    language: Optional[str] = None
    line_start: int = 1
    highlighted_line: Optional[int] = None

    def with_line_numbers(self) -> str:
        """Get the code snippet with line numbers.

        Returns:
            Code snippet with line numbers
        """
        lines = self.code.split('\n')
        result = []

        for i, line in enumerate(lines):
            line_num = self.line_start + i
            prefix = ">" if line_num == self.highlighted_line else " "
            result.append(f"{prefix} {line_num}: {line}")

        return '\n'.join(result)


@dataclass
class Finding:
    """Base class for all findings."""

    id: str
    title: str
    description: str
    severity: SeverityLevel
    location: Optional[CodeLocation] = None
    snippet: Optional[CodeSnippet] = None
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_str(self) -> str:
        """Get the severity as a string.

        Returns:
            Severity string
        """
        return self.severity.value

    @property
    def has_location(self) -> bool:
        """Check if the finding has a location.

        Returns:
            True if the finding has a location, False otherwise
        """
        return self.location is not None

    @property
    def has_snippet(self) -> bool:
        """Check if the finding has a code snippet.

        Returns:
            True if the finding has a code snippet, False otherwise
        """
        return self.snippet is not None


@dataclass
class SecurityVulnerability(Finding):
    """Security vulnerability finding."""

    type: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None

    @property
    def is_critical(self) -> bool:
        """Check if the vulnerability is critical.

        Returns:
            True if the vulnerability is critical, False otherwise
        """
        return self.severity == SeverityLevel.CRITICAL

    @property
    def has_remediation(self) -> bool:
        """Check if the vulnerability has a remediation.

        Returns:
            True if the vulnerability has a remediation, False otherwise
        """
        return self.remediation is not None


@dataclass(kw_only=True)
class CodeSmell(Finding):
    """Code smell finding."""

    type: str
    effort_to_fix: str = "medium"  # low, medium, high

    @property
    def is_major(self) -> bool:
        """Check if the code smell is major.

        Returns:
            True if the code smell is major, False otherwise
        """
        return self.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)


@dataclass
class ArchitectureIssue(Finding):
    """Architecture issue finding."""

    components: List[str] = field(default_factory=list)
    patterns_violated: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PerformanceIssue(Finding):
    """Performance issue finding."""

    impact: str = "medium"  # low, medium, high
    optimization_suggestion: Optional[str] = None
    benchmark_data: Optional[Dict[str, Any]] = None

    @property
    def has_benchmark(self) -> bool:
        """Check if the issue has benchmark data.

        Returns:
            True if the issue has benchmark data, False otherwise
        """
        return self.benchmark_data is not None


@dataclass(kw_only=True)
class BestPracticeViolation(Finding):
    """Best practice violation finding."""

    practice_name: str
    reference_url: Optional[str] = None
    fix_example: Optional[str] = None


@dataclass(kw_only=True)
class Recommendation(Finding):
    """Recommendation for improvement."""

    category: str
    effort: str = "medium"  # low, medium, high
    benefit: str = "medium"  # low, medium, high
    examples: List[str] = field(default_factory=list)

    @property
    def priority(self) -> int:
        """Get the priority of the recommendation.

        Returns:
            Priority value (higher is higher priority)
        """
        # Convert effort and benefit to numeric values
        effort_values = {"low": 3, "medium": 2, "high": 1}
        benefit_values = {"low": 1, "medium": 2, "high": 3}

        effort_value = effort_values.get(self.effort.lower(), 2)
        benefit_value = benefit_values.get(self.benefit.lower(), 2)

        # Priority = benefit / effort
        return benefit_value * self.severity.numeric_value / effort_value


@dataclass
class FindingCollection:
    """Collection of findings."""

    repository_path: str
    security_vulnerabilities: List[SecurityVulnerability] = field(default_factory=list)
    code_smells: List[CodeSmell] = field(default_factory=list)
    architecture_issues: List[ArchitectureIssue] = field(default_factory=list)
    performance_issues: List[PerformanceIssue] = field(default_factory=list)
    best_practice_violations: List[BestPracticeViolation] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Get the total number of findings.

        Returns:
            Total number of findings
        """
        return (len(self.security_vulnerabilities) +
                len(self.code_smells) +
                len(self.architecture_issues) +
                len(self.performance_issues) +
                len(self.best_practice_violations) +
                len(self.recommendations))

    @property
    def critical_findings(self) -> List[Finding]:
        """Get all critical findings.

        Returns:
            List of critical findings
        """
        critical = []

        for finding_list in [
            self.security_vulnerabilities,
            self.code_smells,
            self.architecture_issues,
            self.performance_issues,
            self.best_practice_violations
        ]:
            critical.extend([f for f in finding_list if f.severity == SeverityLevel.CRITICAL])

        return critical

    def findings_by_severity(self) -> Dict[SeverityLevel, List[Finding]]:
        """Get findings grouped by severity.

        Returns:
            Dictionary mapping severity levels to lists of findings
        """
        result = {level: [] for level in SeverityLevel}

        # Combine all findings
        all_findings = []
        all_findings.extend(self.security_vulnerabilities)
        all_findings.extend(self.code_smells)
        all_findings.extend(self.architecture_issues)
        all_findings.extend(self.performance_issues)
        all_findings.extend(self.best_practice_violations)
        all_findings.extend(self.recommendations)

        # Group by severity
        for finding in all_findings:
            result[finding.severity].append(finding)

        return result

    def findings_by_file(self) -> Dict[str, List[Finding]]:
        """Get findings grouped by file.

        Returns:
            Dictionary mapping file paths to lists of findings
        """
        result = {}

        # Combine all findings
        all_findings = []
        all_findings.extend(self.security_vulnerabilities)
        all_findings.extend(self.code_smells)
        all_findings.extend(self.architecture_issues)
        all_findings.extend(self.performance_issues)
        all_findings.extend(self.best_practice_violations)

        # Group by file
        for finding in all_findings:
            if finding.location:
                file_path = finding.location.file_path
                if file_path not in result:
                    result[file_path] = []
                result[file_path].append(finding)

        return result

    def prioritized_recommendations(self, limit: Optional[int] = None) -> List[Recommendation]:
        """Get recommendations sorted by priority.

        Args:
            limit: Optional limit on the number of recommendations

        Returns:
            List of recommendations sorted by priority
        """
        sorted_recommendations = sorted(
            self.recommendations,
            key=lambda r: r.priority,
            reverse=True
        )

        if limit:
            return sorted_recommendations[:limit]
        return sorted_recommendations

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the collection.

        Args:
            finding: Finding to add
        """
        if isinstance(finding, SecurityVulnerability):
            self.security_vulnerabilities.append(finding)
        elif isinstance(finding, CodeSmell):
            self.code_smells.append(finding)
        elif isinstance(finding, ArchitectureIssue):
            self.architecture_issues.append(finding)
        elif isinstance(finding, PerformanceIssue):
            self.performance_issues.append(finding)
        elif isinstance(finding, BestPracticeViolation):
            self.best_practice_violations.append(finding)
        elif isinstance(finding, Recommendation):
            self.recommendations.append(finding)
        else:
            raise ValueError(f"Unknown finding type: {type(finding)}")

    def get_findings_with_tag(self, tag: str) -> List[Finding]:
        """Get all findings with a specific tag.

        Args:
            tag: Tag to search for

        Returns:
            List of findings with the specified tag
        """
        findings = []

        for finding_list in [
            self.security_vulnerabilities,
            self.code_smells,
            self.architecture_issues,
            self.performance_issues,
            self.best_practice_violations,
            self.recommendations
        ]:
            findings.extend([f for f in finding_list if tag in f.tags])

        return findings