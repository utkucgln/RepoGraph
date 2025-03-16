"""
Security-focused repository analysis example.

This example demonstrates how to set up and run a security-focused
repository analysis workflow using the refactored code.
"""

import os
import sys
import logging
from pathlib import Path

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.utils.logging_utils import setup_logging
from src.config.settings import Config
from src.llm.provider import LLMProvider
from src.core.agent_factory import AgentFactory
from src.core.workflow import WorkflowBuilder


def main():
    """Run a security-focused repository analysis workflow."""
    # Set up logging
    logger = setup_logging(
        log_level="INFO",
        log_file="logs/security_analysis.log"
    )
    logger.info("Starting security-focused repository analysis")

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Security-Focused Repository Analyzer")
    parser.add_argument("--repo-path", type=str, required=True, help="Path to the repository to analyze")
    parser.add_argument("--config", type=str, help="Path to a configuration file")
    parser.add_argument("--output", type=str, default="reports/security_report.md",
                        help="Path to save the security report")
    args = parser.parse_args()

    # Create configuration
    config = Config(args.config)

    # Create LLM provider
    llm_provider = LLMProvider(
        provider_name=config.get("llm", "provider", default="openai"),
        config=config.get("llm")
    )
    logger.info(f"Using LLM provider: {config.get('llm', 'provider', default='openai')}")
    logger.info(f"Available models: {llm_provider.list_available_models()}")

    # Create agent factory
    agent_factory = AgentFactory(llm_provider, config.as_dict())

    # Register agent classes
    from src.agents import AGENT_CLASSES
    for agent_name, agent_class in AGENT_CLASSES.items():
        agent_factory.register_agent(agent_name, agent_class)

    # Create workflow builder
    workflow_builder = WorkflowBuilder(config, llm_provider, agent_factory)

    # Create and run a security analysis workflow
    workflow = workflow_builder.create_security_workflow()
    # Set up initial state with repository path
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": f"Please perform a security analysis on the repository at the following Path: {args.repo_path}"
            }
        ]
    }

    # Run the workflow
    logger.info(f"Analyzing repository security at: {args.repo_path}")
    final_state = workflow.run(initial_state)

    # Print completion message
    logger.info("Security analysis complete")

    # Check if the security report was generated
    security_report = None
    for message in final_state.get("messages", []):
        if getattr(message, "name", "") == "security_report" or message.get("name") == "security_report":
            security_report = message
            break

    # If no specific security report, look for the last message from security_agent
    if not security_report:
        for message in reversed(final_state.get("messages", [])):
            role = getattr(message, "role", None) or message.get("role", "")
            name = getattr(message, "name", None) or message.get("name", "")
            if role == "assistant" and name == "security_agent":
                security_report = message
                break

    if security_report:
        report_path = args.output
        report_content = getattr(security_report, "content", None)
        if report_content is None:
            report_content = security_report.get("content", "")

        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        logger.info(f"Security report saved to: {report_path}")
        print(f"Security analysis complete! Report saved to: {report_path}")
    else:
        logger.warning("No security report was generated")
        print("Security analysis completed but no report was generated.")


if __name__ == "__main__":
    main()