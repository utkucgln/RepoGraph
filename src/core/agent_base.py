"""
Base class for all agents in the repository analyzer system.

This module provides the foundation for creating specialized agents that perform
different analysis tasks on code repositories.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable


class Agent(ABC):
    """Base class for all repository analyzer agents.

    All agents in the system should inherit from this class and implement
    the abstract methods to provide their specific functionality.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List[Callable]] = None):
        """Initialize a new agent.

        Args:
            name: The name of the agent
            model: The LLM model to use for this agent
            tools: Optional list of tools the agent can use
        """
        self.name = name
        self.model = model
        self.tools = tools or []
        self.logger = logging.getLogger(f"agent.{name}")

    @abstractmethod
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and perform the agent's specific task.

        This method should be implemented by all agent subclasses to provide
        their specific functionality.

        Args:
            state: The current state dictionary containing context and messages

        Returns:
            Updated state dictionary with the agent's results
        """
        pass

    def add_message_to_state(self, state: Dict[str, Any],
                             content: str, role: str = "system",
                             name: Optional[str] = None) -> Dict[str, Any]:
        """Add a new message to the state.

        Args:
            state: The current state dictionary
            content: The message content to add
            role: The role of the message sender (system, user, assistant)
            name: Optional name for the message

        Returns:
            Updated state with the new message added
        """
        if "messages" not in state:
            state["messages"] = []

        message = {"role": role, "content": content}
        if name:
            message["name"] = name

        state["messages"].append(message)
        return state

    def get_messages_by_name(self, state: Dict[str, Any],
                             name: str) -> List[Dict[str, Any]]:
        """Get all messages with a specific name from the state.

        Args:
            state: The current state dictionary
            name: The name of the messages to retrieve

        Returns:
            List of messages with the specified name
        """
        if "messages" not in state:
            return []

        return [msg for msg in state["messages"]
                if isinstance(msg, dict) and msg.get("name") == name]

    def get_last_message_by_name(self, state: Dict[str, Any],
                                 name: str) -> Optional[Dict[str, Any]]:
        """Get the most recent message with a specific name.

        Args:
            state: The current state dictionary
            name: The name of the message to retrieve

        Returns:
            The most recent message with the specified name, or None if not found
        """
        messages = self.get_messages_by_name(state, name)
        return messages[-1] if messages else None

    def log_debug(self, message: str) -> None:
        """Log a debug message.

        Args:
            message: The message to log
        """
        self.logger.debug(message)

    def log_info(self, message: str) -> None:
        """Log an info message.

        Args:
            message: The message to log
        """
        self.logger.info(message)

    def log_warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message: The message to log
        """
        self.logger.warning(message)

    def log_error(self, message: str) -> None:
        """Log an error message.

        Args:
            message: The message to log
        """
        self.logger.error(message)