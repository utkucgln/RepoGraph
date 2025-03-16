"""
Workflow definitions for repository analyzer with enhanced dynamic prompts.

This module provides functionality for creating and executing
workflows that coordinate multiple agents for repository analysis.
"""

import logging
from typing import Dict, Any, List, Optional, Callable

from src.core.agent_base import Agent
from src.core.supervisor import Supervisor
from src.llm.provider import LLMProvider
from src.core.agent_factory import AgentFactory
from src.config.settings import Config

logger = logging.getLogger("core.workflow")


class Workflow:
    """Workflow for coordinating multi-agent repository analysis.

    A workflow defines a sequence of agents that work together
    to perform a complete repository analysis.
    """

    def __init__(self, name: str, description: str,
                 agents: List[str], supervisor_prompt: str,
                 config: Config, llm_provider: LLMProvider):
        """Initialize a workflow.

        Args:
            name: Name of the workflow
            description: Description of what the workflow does
            agents: List of agent names that make up the workflow
            supervisor_prompt: Prompt to guide the supervisor
            config: Configuration for the workflow
            llm_provider: LLM provider for the workflow
        """
        self.name = name
        self.description = description
        self.agent_names = agents
        self.supervisor_prompt = supervisor_prompt
        self.config = config
        self.llm_provider = llm_provider
        self.agents = {}
        self.supervisor = None
        self.logger = logging.getLogger(f"workflow.{name}")

    def load_agents(self, agent_factory: AgentFactory) -> None:
        """Load all agents needed for this workflow.

        Args:
            agent_factory: Factory for creating agent instances
        """
        self.logger.info(f"Loading {len(self.agent_names)} agents for workflow: {self.name}")

        for agent_name in self.agent_names:
            try:
                self.agents[agent_name] = agent_factory.create_agent(agent_name)
                self.logger.debug(f"Loaded agent: {agent_name}")
            except ValueError as e:
                self.logger.error(f"Failed to load agent {agent_name}: {str(e)}")
                raise

        # Create the supervisor
        supervisor_model = self.llm_provider.get_model(
            self.config.get("llm", "default_model", default="o1")
        )
        self.supervisor = Supervisor(self.agents, supervisor_model, self.supervisor_prompt)
        self.logger.info("Supervisor created successfully")

    def run(self, state: Optional[Dict[str, Any]] = None,
            config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run the workflow.

        Args:
            state: Optional initial state
            config: Optional runtime configuration

        Returns:
            Final state after workflow completion
        """
        if not self.supervisor:
            raise ValueError("Workflow agents not loaded. Call load_agents() first.")

        self.logger.info(f"Starting workflow: {self.name}")
        final_state = self.supervisor.invoke(state, config)
        self.logger.info(f"Workflow {self.name} completed")

        return final_state


class WorkflowBuilder:
    """Builder for creating workflow instances.

    The WorkflowBuilder provides a convenient way to create and
    configure workflows for different repository analysis needs.
    """

    def __init__(self, config: Config, llm_provider: LLMProvider, agent_factory: AgentFactory):
        """Initialize the workflow builder.

        Args:
            config: Configuration for workflows
            llm_provider: LLM provider for the workflows
            agent_factory: Factory for creating agent instances
        """
        self.config = config
        self.llm_provider = llm_provider
        self.agent_factory = agent_factory
        self.logger = logging.getLogger("workflow_builder")

    def create_standard_workflow(self) -> Workflow:
        """Create a standard comprehensive analysis workflow.

        Returns:
            Configured workflow instance
        """
        name = "standard_analysis"
        description = "Standard comprehensive repository analysis workflow"

        agents = [
            "repository_loader",
            "file_analyzer",
            "report_generator",
            "architecture_diagram_generator",
            "critical_method_analyzer",
            "security_agent"
        ]

        supervisor_prompt = """
        You are a highly adaptive team supervisor managing a comprehensive code review and analysis process. 
        Your goal is to intelligently coordinate multiple specialized agents to produce a thorough repository analysis.
        
        Available agents:
        - repository_loader: Scans and loads repository files
        - file_analyzer: Analyzes and describes file purposes and functionality
        - report_generator: Creates comprehensive repository overview
        - architecture_diagram_generator: Creates visual system architecture representations
        - critical_method_analyzer: Identifies and analyzes security-critical methods
        - security_agent: Performs comprehensive security analysis
        
        Context-aware delegation instructions:
        - Analyze the current state and conversation history to determine what has already been accomplished
        - Identify the most logical next step based on dependencies and available information
        - Consider user's specific requirements and priorities when making delegation decisions
        - Prefer the most specialized agent for each task rather than following a rigid sequence
        - Balance thoroughness with efficiency, avoiding redundant analysis
        
        Special cases:
        - If the user mentions "security" or "vulnerabilities" prominently, prioritize security analysis
        - If the user mentions "architecture" or "design" prominently, prioritize architecture analysis
        - If logs or errors are mentioned, prioritize diagnostic and fix-related agents
        - For peer review requests, delegate to peer_review_agent after basic analysis
        
        When all necessary analysis is complete based on user requirements, respond with FINISH.
        """

        workflow = Workflow(
            name=name,
            description=description,
            agents=agents,
            supervisor_prompt=supervisor_prompt,
            config=self.config,
            llm_provider=self.llm_provider
        )

        workflow.load_agents(self.agent_factory)
        return workflow

    def create_security_workflow(self) -> Workflow:
        """Create a security-focused analysis workflow.

        Returns:
            Configured workflow instance
        """
        name = "security_analysis"
        description = "Security-focused repository analysis workflow"

        agents = [
            "repository_loader",
            "file_analyzer",
            "critical_method_analyzer",
            "security_agent"
        ]

        supervisor_prompt = """
        You are an intelligent security team supervisor managing a security-focused code review process.
        Your goal is to comprehensively evaluate repository security through dynamic agent coordination.
        
        Available agents:
        - repository_loader: Scans and loads repository files
        - file_analyzer: Analyzes and describes file purposes and functionality
        - critical_method_analyzer: Identifies and analyzes security-critical methods
        - security_agent: Performs comprehensive security analysis
        
        Context-aware delegation strategy:
        - Assess the current analysis state to determine what information is available
        - Intelligently select the next most appropriate agent based on available data
        - Focus on vulnerability detection while maintaining a complete understanding of the codebase
        - Adapt the analysis depth based on the repository's complexity and security requirements
        - Prioritize analysis of high-risk components identified during the review process
        
        Special considerations:
        - If specific vulnerabilities are mentioned by the user, ensure they receive focused analysis
        - If compliance requirements are mentioned, ensure the security analysis addresses them
        - If the repository uses particular technologies or frameworks, ensure relevant security patterns are evaluated
        - Balance breadth of coverage with depth of analysis based on risk assessment
        
        When a comprehensive security analysis is complete, respond with FINISH.
        """

        workflow = Workflow(
            name=name,
            description=description,
            agents=agents,
            supervisor_prompt=supervisor_prompt,
            config=self.config,
            llm_provider=self.llm_provider
        )

        workflow.load_agents(self.agent_factory)
        return workflow

    def create_code_fix_workflow(self) -> Workflow:
        """Create a code fix workflow.

        Returns:
            Configured workflow instance
        """
        name = "code_fix"
        description = "Workflow for analyzing error logs and providing code fixes"

        agents = [
            "repository_loader",
            "file_analyzer",
            "code_fix_agent"
        ]

        supervisor_prompt = """
        You are a strategic debugging team supervisor managing an error analysis and code fix process.
        Your goal is to efficiently diagnose and solve code issues through intelligent agent coordination.
        
        Available agents:
        - repository_loader: Scans and loads repository files
        - file_analyzer: Analyzes and describes file purposes and functionality
        - code_fix_agent: Analyzes logs and provides code fixes
        
        Adaptive delegation approach:
        - Evaluate the current state to understand what information has been gathered
        - Determine what additional context is needed to effectively diagnose the problem
        - Select agents that can provide the most relevant insights for the specific error type
        - Prioritize understanding dependency chains and interaction patterns relevant to the error
        - Build a progressive understanding of the issue before proposing fixes
        
        Error-specific considerations:
        - For runtime errors, ensure relevant execution paths are analyzed
        - For compilation/build errors, focus on syntax and dependency issues
        - For logical errors, ensure broader functionality context is understood
        - Adapt analysis depth based on error complexity and system criticality
        
        When the issue is diagnosed and appropriate fixes are provided, respond with FINISH.
        """

        workflow = Workflow(
            name=name,
            description=description,
            agents=agents,
            supervisor_prompt=supervisor_prompt,
            config=self.config,
            llm_provider=self.llm_provider
        )

        workflow.load_agents(self.agent_factory)
        return workflow

    def create_peer_review_workflow(self) -> Workflow:
        """Create a peer review workflow.

        Returns:
            Configured workflow instance
        """
        name = "peer_review"
        description = "Workflow for performing a comprehensive peer review"

        agents = [
            "repository_loader",
            "file_analyzer",
            "peer_review_agent"
        ]

        supervisor_prompt = """
        You are a thoughtful peer review team supervisor managing a code review process.
        Your goal is to provide valuable feedback that improves code quality through contextual analysis.
        
        Available agents:
        - repository_loader: Scans and loads repository files
        - file_analyzer: Analyzes and describes file purposes and functionality
        - peer_review_agent: Performs comprehensive peer review
        
        Dynamic review strategy:
        - Assess what contextual information is already available about the codebase
        - Determine what additional understanding is needed for an effective review
        - Focus analysis on areas that will provide the most valuable feedback
        - Adapt review depth based on code complexity, criticality, and team standards
        - Consider both technical implementation and design principles in the review
        
        Review focus adaptation:
        - If performance is mentioned, ensure optimization opportunities are evaluated
        - If maintainability is highlighted, focus on structure, patterns, and documentation
        - If specific features are mentioned, prioritize their implementation review
        - Balance identifying issues with suggesting improvements and highlighting strengths
        
        When a thorough and constructive review is complete, respond with FINISH.
        """

        workflow = Workflow(
            name=name,
            description=description,
            agents=agents,
            supervisor_prompt=supervisor_prompt,
            config=self.config,
            llm_provider=self.llm_provider
        )

        workflow.load_agents(self.agent_factory)
        return workflow

    def create_custom_workflow(self, name: str, description: str,
                               agents: List[str], supervisor_prompt: str) -> Workflow:
        """Create a custom workflow.

        Args:
            name: Name of the workflow
            description: Description of what the workflow does
            agents: List of agent names that make up the workflow
            supervisor_prompt: Prompt to guide the supervisor

        Returns:
            Configured workflow instance
        """
        workflow = Workflow(
            name=name,
            description=description,
            agents=agents,
            supervisor_prompt=supervisor_prompt,
            config=self.config,
            llm_provider=self.llm_provider
        )

        workflow.load_agents(self.agent_factory)
        return workflow