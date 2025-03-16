"""
Report data models.

This module provides data models for representing analysis reports
and their components.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime


class ReportFormat(Enum):
    """Report output formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class ReportSection:
    """Section of a report."""

    title: str
    content: str
    subsections: List["ReportSection"] = field(default_factory=list)
    order: int = 0

    @property
    def has_subsections(self) -> bool:
        """Check if the section has subsections.

        Returns:
            True if the section has subsections, False otherwise
        """
        return len(self.subsections) > 0

    def add_subsection(self, subsection: "ReportSection") -> None:
        """Add a subsection.

        Args:
            subsection: Subsection to add
        """
        self.subsections.append(subsection)

    def get_markdown(self, level: int = 1) -> str:
        """Get the section as markdown.

        Args:
            level: Heading level

        Returns:
            Markdown representation of the section
        """
        heading = "#" * level
        result = f"{heading} {self.title}\n\n{self.content}\n\n"

        # Add subsections
        for subsection in sorted(self.subsections, key=lambda s: s.order):
            result += subsection.get_markdown(level + 1)

        return result


@dataclass
class DiagramInfo:
    """Diagram information for reports."""

    title: str
    type: str  # component, sequence, class, etc.
    content: str
    description: Optional[str] = None

    def get_markdown(self) -> str:
        """Get the diagram as markdown.

        Returns:
            Markdown representation of the diagram
        """
        result = f"### {self.title}\n\n"

        if self.description:
            result += f"{self.description}\n\n"

        result += f"```mermaid\n{self.content}\n```\n\n"

        return result


@dataclass
class MetricValue:
    """Metric value for reports."""

    name: str
    value: Any
    description: Optional[str] = None
    unit: Optional[str] = None

    def get_formatted_value(self) -> str:
        """Get the formatted value with unit.

        Returns:
            Formatted value string
        """
        if self.unit:
            return f"{self.value} {self.unit}"
        return str(self.value)

    def get_markdown(self) -> str:
        """Get the metric as markdown.

        Returns:
            Markdown representation of the metric
        """
        result = f"**{self.name}**: {self.get_formatted_value()}"

        if self.description:
            result += f" - {self.description}"

        return result


@dataclass
class TableData:
    """Table data for reports."""

    headers: List[str]
    rows: List[List[Any]]
    caption: Optional[str] = None

    def get_markdown(self) -> str:
        """Get the table as markdown.

        Returns:
            Markdown representation of the table
        """
        result = ""

        if self.caption:
            result += f"*{self.caption}*\n\n"

        # Build header row
        result += "| " + " | ".join(self.headers) + " |\n"

        # Build separator row
        result += "| " + " | ".join(["---"] * len(self.headers)) + " |\n"

        # Build data rows
        for row in self.rows:
            result += "| " + " | ".join(str(cell) for cell in row) + " |\n"

        result += "\n"
        return result


@dataclass
class RepositoryReport:
    """Complete repository analysis report."""

    repository_path: str
    repository_name: str
    created_at: datetime = field(default_factory=datetime.now)
    sections: List[ReportSection] = field(default_factory=list)
    diagrams: List[DiagramInfo] = field(default_factory=list)
    metrics: List[MetricValue] = field(default_factory=list)
    tables: Dict[str, TableData] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def section_count(self) -> int:
        """Get the number of top-level sections.

        Returns:
            Number of top-level sections
        """
        return len(self.sections)

    def add_section(self, section: ReportSection) -> None:
        """Add a top-level section.

        Args:
            section: Section to add
        """
        self.sections.append(section)

    def get_section(self, title: str) -> Optional[ReportSection]:
        """Get a section by title.

        Args:
            title: Title of the section

        Returns:
            Section with the specified title, or None if not found
        """
        for section in self.sections:
            if section.title == title:
                return section
        return None

    def add_diagram(self, diagram: DiagramInfo) -> None:
        """Add a diagram.

        Args:
            diagram: Diagram to add
        """
        self.diagrams.append(diagram)

    def add_metric(self, metric: MetricValue) -> None:
        """Add a metric.

        Args:
            metric: Metric to add
        """
        self.metrics.append(metric)

    def add_table(self, name: str, table: TableData) -> None:
        """Add a table.

        Args:
            name: Name/key for the table
            table: Table to add
        """
        self.tables[name] = table

    def get_markdown(self) -> str:
        """Get the report as markdown.

        Returns:
            Markdown representation of the report
        """
        result = f"# {self.repository_name} Analysis Report\n\n"
        result += f"*Generated on: {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}*\n\n"

        # Table of contents
        result += "## Table of Contents\n\n"
        for i, section in enumerate(sorted(self.sections, key=lambda s: s.order)):
            result += f"{i + 1}. [{section.title}](#{section.title.lower().replace(' ', '-')})\n"
        result += "\n"

        # Summary metrics
        if self.metrics:
            result += "## Key Metrics\n\n"
            for metric in self.metrics:
                result += f"- {metric.get_markdown()}\n"
            result += "\n"

        # Main content sections
        for section in sorted(self.sections, key=lambda s: s.order):
            result += section.get_markdown(level=2)

        # Diagrams section
        if self.diagrams:
            result += "## Architecture Diagrams\n\n"
            for diagram in self.diagrams:
                result += diagram.get_markdown()

        # Appendices (tables, etc.)
        if self.tables:
            result += "## Appendices\n\n"
            for name, table in self.tables.items():
                result += f"### {name}\n\n"
                result += table.get_markdown()

        return result

    def get_html(self) -> str:
        """Get the report as HTML.

        Returns:
            HTML representation of the report
        """
        # This is a simplified HTML output
        # A real implementation would have proper styling and formatting
        markdown = self.get_markdown()

        try:
            import markdown as md
            html = md.markdown(markdown, extensions=['tables', 'fenced_code'])

            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{self.repository_name} Analysis Report</title>
                <style>
                    body {{ font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 20px; }}
                    h1, h2, h3, h4, h5, h6 {{ margin-top: 1.5em; margin-bottom: 0.5em; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    code {{ background-color: #f5f5f5; padding: 2px 4px; border-radius: 4px; }}
                    pre {{ background-color: #f5f5f5; padding: 1em; overflow-x: auto; border-radius: 4px; }}
                </style>
            </head>
            <body>
                {html}
            </body>
            </html>
            """
        except ImportError:
            # Fall back to basic HTML if markdown module is not available
            return f"<html><body><pre>{markdown}</pre></body></html>"

    def save(self, output_path: str, format: ReportFormat = ReportFormat.MARKDOWN) -> None:
        """Save the report to a file.

        Args:
            output_path: Path to save the report to
            format: Format of the report
        """
        with open(output_path, "w", encoding="utf-8") as f:
            if format == ReportFormat.MARKDOWN:
                f.write(self.get_markdown())
            elif format == ReportFormat.HTML:
                f.write(self.get_html())
            elif format == ReportFormat.JSON:
                import json
                # Convert to dict using __dict__, this is a simplification
                json.dump({
                    "repository_path": self.repository_path,
                    "repository_name": self.repository_name,
                    "created_at": self.created_at.isoformat(),
                    "sections": [vars(s) for s in self.sections],
                    "diagrams": [vars(d) for d in self.diagrams],
                    "metrics": [vars(m) for m in self.metrics],
                    "tables": {name: vars(table) for name, table in self.tables.items()},
                    "metadata": self.metadata
                }, f, indent=2)
            elif format == ReportFormat.TEXT:
                f.write(self.get_markdown())  # Fallback to markdown for text
            else:
                raise ValueError(f"Unsupported format: {format}")