"""
Supervisor for orchestrating dynamic multi-agent workflows using LLM decision-making.

This module provides a supervisor that coordinates the execution
of multiple agents in a dynamic workflow determined by LLM reasoning.
"""

import logging
import json
from typing import Dict, Any, List, Callable, Optional, Tuple
import re
from src.core.agent_base import Agent
from src.core.state_manager import StateManager

logger = logging.getLogger("core.supervisor")


class Supervisor:
    """Dynamic supervisor for LLM-orchestrated multi-agent workflows.

    The DynamicSupervisor coordinates the execution of multiple agents by
    using an LLM to decide which agent to run next based on the current state,
    user query, and available agents.
    """

    def __init__(self, agents: Dict[str, Agent], llm_model: Any, system_prompt: str = None):
        """Initialize the dynamic supervisor.

        Args:
            agents: Dictionary mapping agent names to agent instances
            llm_model: LLM model for making workflow decisions
            system_prompt: System prompt describing the decision-making process
        """
        self.agents = agents
        self.model = llm_model
        self.state_manager = StateManager()
        self.logger = logging.getLogger("supervisor")

        # Default system prompt if none provided
        self.system_prompt = system_prompt or self._get_default_system_prompt()

    def invoke(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run the supervisor workflow.

        Args:
            state: Initial state dictionary
            config: Optional configuration for the workflow

        Returns:
            Updated state dictionary after workflow completion
        """
        config = config or {}
        self.logger.info("Starting dynamic supervisor workflow")

        # Create a new state if not provided
        if not state:
            repo_path = config.get("repo_path", ".")
            state = self.state_manager.create_state(repo_path)
        elif "repo_path" in config and "repo_path" not in state:
            state["repo_path"] = config.get("repo_path")

        # Get the most recent user message
        user_message = self._get_latest_user_message(state)

        # Main workflow loop
        max_iterations = config.get("max_iterations", 10)  # Prevent infinite loops
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            # Decide which agent to run next using LLM
            next_agent, reason = self._llm_decide_next_agent(state, user_message)

            # If no agent is selected or FINISH is returned, we're done
            if next_agent == "FINISH" or not next_agent:
                self.logger.info(f"Workflow complete: {reason}")
                break

            # Run the selected agent
            agent_name = next_agent
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                self.logger.info(f"Running agent: {agent_name} (Reason: {reason})")

                try:
                    # Save state before agent execution
                    before_state = state.copy()

                    # Execute the agent
                    state = agent.invoke(state)

                    # Update state with completion marker
                    self.state_manager.mark_stage_complete(state, agent_name)

                    # Save the state
                    self.state_manager.save_state(state)

                    # Log state changes
                    from src.utils.logging_utils import log_state_changes
                    log_state_changes(before_state, state)

                except Exception as e:
                    self.logger.error(f"Error executing agent {agent_name}: {str(e)}")
                    # Add error message to state
                    if "messages" not in state:
                        state["messages"] = []
                    state["messages"].append({
                        "role": "system",
                        "content": f"Error executing agent {agent_name}: {str(e)}",
                        "name": "error"
                    })
            else:
                self.logger.error(f"Unknown agent: {agent_name}")
                # Add error message to state
                if "messages" not in state:
                    state["messages"] = []
                state["messages"].append({
                    "role": "system",
                    "content": f"Unknown agent: {agent_name}",
                    "name": "error"
                })

        self.logger.info(f"Dynamic supervisor workflow completed after {iteration} iterations")
        return state

    def _get_latest_user_message(self, state: Dict[str, Any]) -> str:
        """Extract the most recent user message from the state.

        Args:
            state: Current state dictionary

        Returns:
            The most recent user message or empty string if none found
        """
        messages = state.get("messages", [])
        for message in reversed(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                return message.get("content", "")
        return ""

    def _llm_decide_next_agent(self, state: Dict[str, Any], user_message: str) -> Tuple[Optional[str], str]:
        """Use LLM to decide which agent to run next based on the current state.

        Args:
            state: Current state dictionary
            user_message: The most recent user message

        Returns:
            Tuple of (agent_name, reason) or ("FINISH", reason) if workflow is complete
        """
        # Prepare the context for the LLM
        completed_stages = state.get("completed_stages", [])
        available_agents = list(self.agents.keys())

        # Create a state summary for the LLM
        state_summary = {
            "repo_path": state.get("repo_path", ""),
            "completed_stages": completed_stages,
            "available_agents": available_agents
        }

        # Additional context from the state that might be useful
        if "file_summary" in state:
            state_summary["file_summary"] = state.get("file_summary")
        if "architecture_summary" in state:
            state_summary["architecture_summary"] = state.get("architecture_summary")
        if "security_issues" in state:
            state_summary["security_issues"] = state.get("security_issues")

        # Prepare the prompt for the LLM
        prompt = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""
User query: {user_message}

Current state:
{json.dumps(state_summary, indent=2)}

Available agents: {', '.join(available_agents)}
Completed stages: {', '.join(completed_stages)}

Based on the user query and current state, which agent should be run next?
Respond with a JSON object containing:
1. "next_agent": The name of the next agent to run, or "FINISH" if the workflow is complete
2. "reasoning": A detailed explanation of why this agent was chosen
"""}
        ]

        # Get LLM response
        try:

            # response = self.model.generate(prompt)
            # response_content = response.get("choices", [{}])[0].get("message", {}).get("content", "")

            response = self.model.invoke(prompt)
            try:
                # Extract JSON from the response
                json_pattern = r'```(?:json)?\n(.*?)\n```'
                match = re.search(json_pattern, response.content, re.DOTALL)

                if match:
                    decision = json.loads(match.group(1))
                    next_agent = decision.get("next_agent")
                    reasoning = decision.get("reasoning", "No reasoning provided")
                    if next_agent == "FINISH":
                        return "FINISH", reasoning
                    elif next_agent in available_agents:
                        return next_agent, reasoning
                    else:
                        self.logger.warning(f"LLM returned invalid agent: {next_agent}")
                        return None, f"Invalid agent selection: {next_agent}"

            except json.JSONDecodeError:
                self.logger.error(f"Failed to parse LLM response as JSON: {response.content}")
                # Fallback: Try to extract agent name using simple text parsing
                if "FINISH" in response.content:
                    return "FINISH", "LLM decided workflow is complete (fallback parsing)"

                for agent in available_agents:
                    if agent in response.content:
                        return agent, f"Agent mentioned in LLM response (fallback parsing)"

                return None, "Could not determine next agent from LLM response"

        except Exception as e:
            self.logger.error(f"Error getting LLM decision: {str(e)}")
            # Fallback: Use a simple heuristic
            return self._fallback_decide_next_agent(state, user_message)

    def _fallback_decide_next_agent(self, state: Dict[str, Any], user_message: str) -> Tuple[Optional[str], str]:
        """Fallback method to decide next agent if LLM decision fails.

        Args:
            state: Current state dictionary
            user_message: The most recent user message

        Returns:
            Tuple of (agent_name, reason) or ("FINISH", reason) if workflow is complete
        """
        completed_stages = state.get("completed_stages", [])
        available_agents = list(self.agents.keys())

        # Basic sequential workflow as fallback
        standard_workflow = [
            "repository_loader",
            "file_analyzer",
            "report_generator",
            "architecture_diagram_generator",
            "critical_method_analyzer",
            "security_agent"
        ]

        for agent in standard_workflow:
            if agent in available_agents and agent not in completed_stages:
                return agent, f"Fallback selection (standard workflow order)"

        return "FINISH", "All standard agents completed (fallback decision)"

    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for LLM agent selection.

        Returns:
            Default system prompt string
        """
        return """
You are an expert workflow orchestrator for a code analysis system. Your job is to decide which agent should be executed next in a multi-agent workflow based on the user's query and the current state of the analysis.

The available agents are:
1. repository_loader - Loads and indexes the repository files
2. file_analyzer - Analyzes the content and structure of files
3. report_generator - Generates a comprehensive report about the codebase
4. architecture_diagram_generator - Creates architecture diagrams
5. critical_method_analyzer - Identifies and analyzes critical methods
6. security_agent - Performs security analysis
7. code_fix_agent - Implements code fixes
8. peer_review_agent - Performs peer code review

You need to decide which agent should run next or if the workflow is complete.

Consider:
- The user's specific request
- Which agents have already run (completed_stages)
- The logical dependencies between agents (e.g., repository must be loaded before analysis)
- Whether the user's request has been fully addressed

Respond with a JSON object containing:
1. "next_agent": Name of the next agent to run, or "FINISH" if the workflow is complete
2. "reasoning": Detailed explanation of why this agent should run next
"""