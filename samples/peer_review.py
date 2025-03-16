"""
Peer review example script.

This script demonstrates how to run a peer review on a repository
using the refactored repository analyzer.
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.utils.logging_utils import setup_logging
from src.config.settings import Config
from src.llm.provider import LLMProvider
from src.core.agent_factory import AgentFactory
from src.core.workflow import WorkflowBuilder
from src.agents import AGENT_CLASSES


def main():
    """Run a peer review workflow."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Repository Peer Review")
    parser.add_argument("--repo-path", type=str,
                        help="Path to the repository to review")
    parser.add_argument("--config", type=str, help="Path to a configuration file")
    parser.add_argument("--output-dir", type=str, default="reports",
                        help="Directory to save reports in")
    parser.add_argument("--log-level", type=str, default="INFO",
                        help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    # Set up logging
    logger = setup_logging(
        log_level=args.log_level,
        log_file=os.path.join(args.output_dir, "peer_review.log")
    )
    logger.info(f"Starting peer review for repository: {args.repo_path}")

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Create configuration
    config = Config(args.config)

    # Override output directory in config
    config.set(args.output_dir, "output", "directory")

    # Create LLM provider
    llm_provider = LLMProvider(
        provider_name=config.get("llm", "provider", default="openai"),
        config=config.get("llm")
    )
    logger.info(f"Using LLM provider: {config.get('llm', 'provider', default='openai')}")

    # Create agent factory
    agent_factory = AgentFactory(llm_provider, config.as_dict())

    # Register agent classes
    for agent_name, agent_class in AGENT_CLASSES.items():
        agent_factory.register_agent(agent_name, agent_class)

    # Create workflow builder
    workflow_builder = WorkflowBuilder(config, llm_provider, agent_factory)

    # Create and run a peer review workflow
    workflow = workflow_builder.create_peer_review_workflow()

    # Set up initial state with repository path
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": f"Please perform a peer review of the repository at the following path: {args.repo_path}"
            }
        ],
        "repo_path": args.repo_path
    }

    # Run the workflow
    logger.info(f"Starting peer review workflow for repository: {args.repo_path}")
    final_state = workflow.run(initial_state)

    # Check if the peer review was completed
    peer_review_message = None
    for message in final_state.get("messages", []):
        if getattr(message, "name", "") == "peer_review" or message.get("name") == "peer_review":
            peer_review_message = message
            break

if __name__ == "__main__":
    main()