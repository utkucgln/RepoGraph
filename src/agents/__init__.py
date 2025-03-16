"""
Agents package for repository analyzer.

This package contains all the specialized agents for repository analysis.
"""

# Import agents for easy access
from src.agents.repository.loader import RepositoryLoaderAgent
from src.agents.repository.qa_agent import RepositoryQAAgent
from src.agents.analysis.file_analyzer import FileAnalyzerAgent
from src.agents.analysis.report_generator import ReportGeneratorAgent
from src.agents.visualization.architecture_diagrammer import ArchitectureDiagramGeneratorAgent
from src.agents.security.critical_method_analyzer import CriticalMethodAnalyzerAgent
from src.agents.security.security_analyzer import SecurityAnalyzerAgent
from src.agents.code_quality.code_fix_agent import CodeFixAgent
from src.agents.code_quality.peer_review_agent import PeerReviewAgent

# Define a mapping of agent names to their classes
AGENT_CLASSES = {
    "repository_loader": RepositoryLoaderAgent,
    "repository_qa_agent": RepositoryQAAgent,
    "file_analyzer": FileAnalyzerAgent,
    "report_generator": ReportGeneratorAgent,
    "architecture_diagram_generator": ArchitectureDiagramGeneratorAgent,
    "critical_method_analyzer": CriticalMethodAnalyzerAgent,
    "security_agent": SecurityAnalyzerAgent,
    "code_fix_agent": CodeFixAgent,
    "peer_review_agent": PeerReviewAgent
}

def get_agent_class(agent_name):
    """Get the agent class for a given agent name.

    Args:
        agent_name: Name of the agent

    Returns:
        Agent class, or None if not found
    """
    return AGENT_CLASSES.get(agent_name)

def list_available_agents():
    """List all available agent names.

    Returns:
        List of available agent names
    """
    return list(AGENT_CLASSES.keys())