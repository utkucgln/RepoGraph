"""
State management for the repository analyzer system.

This module handles the creation, persistence, and retrieval of
state data shared between agents during analysis, keeping all states in memory.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List


class StateManager:
    """Manages state data for analysis workflows in memory.

    The StateManager is responsible for creating, updating, and retrieving
    the shared state used by all agents during repository analysis.
    """

    def __init__(self):
        """Initialize a state manager with an in-memory states dictionary."""
        self.states = {}  # Dictionary to store all states in memory, keyed by state_id

    def create_state(self, repo_path: str) -> Dict[str, Any]:
        """Create a new state for analyzing a repository.

        Args:
            repo_path: Path to the repository being analyzed

        Returns:
            A new state dictionary with initial values
        """
        state_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        state = {
            "id": state_id,
            "created_at": timestamp,
            "updated_at": timestamp,
            "repo_path": repo_path,
            "messages": [
                {
                    "role": "system",
                    "content": f"Path: {repo_path}"
                }
            ],
            "completed_stages": []
        }

        # Save the initial state in memory
        self.save_state(state)
        return state

    def save_state(self, state: Dict[str, Any]) -> None:
        """Save the current state to the in-memory dictionary.

        Args:
            state: The state dictionary to save
        """
        state_id = state.get("id")
        if not state_id:
            state_id = str(uuid.uuid4())
            state["id"] = state_id

        state["updated_at"] = datetime.now().isoformat()

        # Store in the in-memory dictionary
        self.states[state_id] = state

    def load_state(self, state_id: str) -> Optional[Dict[str, Any]]:
        """Load a state from memory by its ID.

        Args:
            state_id: The ID of the state to load

        Returns:
            The state dictionary if found, None otherwise
        """
        return self.states.get(state_id)

    def list_states(self) -> List[Dict[str, Any]]:
        """List all available states.

        Returns:
            List of state metadata dictionaries
        """
        states_list = []
        for state_id, state in self.states.items():
            # Include only metadata in the listing
            states_list.append({
                "id": state.get("id"),
                "created_at": state.get("created_at"),
                "updated_at": state.get("updated_at"),
                "repo_path": state.get("repo_path"),
                "completed_stages": state.get("completed_stages", [])
            })
        return states_list

    def mark_stage_complete(self, state: Dict[str, Any], stage_name: str) -> Dict[str, Any]:
        """Mark an analysis stage as complete in the state.

        Args:
            state: The current state dictionary
            stage_name: Name of the completed stage

        Returns:
            Updated state with the stage marked as complete
        """
        if "completed_stages" not in state:
            state["completed_stages"] = []

        if stage_name not in state["completed_stages"]:
            state["completed_stages"].append(stage_name)
            self.save_state(state)

        return state

    def is_stage_complete(self, state: Dict[str, Any], stage_name: str) -> bool:
        """Check if an analysis stage is marked as complete.

        Args:
            state: The current state dictionary
            stage_name: Name of the stage to check

        Returns:
            True if the stage is complete, False otherwise
        """
        return stage_name in state.get("completed_stages", [])