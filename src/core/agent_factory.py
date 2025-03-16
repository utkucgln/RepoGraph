"""
Factory for creating agent instances.

This module centralizes agent creation and configuration,
making it easier to manage agent dependencies and settings.
"""

import logging
from typing import Dict, Any, Type, Optional, List, Callable

from src.core.agent_base import Agent
from src.llm.provider import LLMProvider


class AgentFactory:
    """Factory for creating and configuring agent instances.

    The AgentFactory is responsible for instantiating agents with the
    appropriate configuration and dependencies.
    """

    def __init__(self, llm_provider: LLMProvider, config: Dict[str, Any]):
        """Initialize the agent factory.

        Args:
            llm_provider: The LLM provider to use for creating language models
            config: Configuration dictionary for agent settings
        """
        self.llm_provider = llm_provider
        self.config = config
        self.logger = logging.getLogger("agent_factory")
        self._registered_agents = {}

    def register_agent(self, agent_name: str, agent_class: Type[Agent]) -> None:
        """Register an agent class with the factory.

        Args:
            agent_name: The name to register the agent under
            agent_class: The agent class to register
        """
        self.logger.info(f"Registering agent: {agent_name}")
        self._registered_agents[agent_name] = agent_class

    def create_agent(self, agent_name: str,
                     tools: Optional[List[Callable]] = None,
                     model_name: Optional[str] = None) -> Agent:
        """Create an agent instance.

        Args:
            agent_name: Name of the agent to create
            tools: Optional list of tools to provide to the agent
            model_name: Optional specific model to use (falls back to config)

        Returns:
            An initialized agent instance

        Raises:
            ValueError: If the agent name is not registered
        """
        if agent_name not in self._registered_agents:
            self.logger.error(f"Unknown agent: {agent_name}")
            raise ValueError(f"Unknown agent: {agent_name}")

        # Get the agent-specific config, or an empty dict if not found
        agent_config = self.config.get("agents", {}).get(agent_name, {})

        # Determine which model to use (specified model, agent config, or default)
        if not model_name:
            model_name = agent_config.get("model_name", self.config.get("default_model"))

        # Get the LLM model
        model = self.llm_provider.get_model(model_name)

        # Create the agent instance
        agent_class = self._registered_agents[agent_name]
        agent = agent_class(
            name=agent_name,
            model=model,
            tools=tools
        )

        self.logger.info(f"Created agent: {agent_name} with model: {model_name}")
        return agent

    def get_registered_agent_names(self) -> List[str]:
        """Get a list of all registered agent names.

        Returns:
            List of registered agent names
        """
        return list(self._registered_agents.keys())