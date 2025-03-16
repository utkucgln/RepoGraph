"""
Basic repository analysis example.

This example demonstrates how to set up and run a basic
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
    """Run a basic repository analysis workflow."""
    # Set up logging
    logger = setup_logging(
        log_level="INFO",
        log_file="logs/repository_analysis.log"
    )
    logger.info("Starting basic repository analysis")

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Repository Analyzer")
    parser.add_argument("--repo-path", type=str, default=".", help="Path to the repository to analyze")
    parser.add_argument("--config", type=str, help="Path to a configuration file")
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

    # Create and run a standard analysis workflow
    workflow = workflow_builder.create_standard_workflow()

    # Set up initial state with repository path
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": f"Please analyze the repository at the following Path: {args.repo_path}"
            }
        ]
    }

    # Run the workflow
    logger.info(f"Analyzing repository at: {args.repo_path}")
    final_state = workflow.run(initial_state)

    # Print completion message
    logger.info("Repository analysis complete")

    # Check if the report was generated
    report_message = None
    for message in final_state.get("messages", []):
        if getattr(message, "name", "") == "report" or message.get("name") == "report":
            report_message = message
            break

    if report_message:
        report_path = "reports/developer_guide.md"
        report_content = getattr(report_message, "content", None)
        if report_content is None:
            report_content = report_message.get("content", "")

        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Report saved to: {report_path}")
        print(f"Analysis complete! Report saved to: {report_path}")
    else:
        logger.warning("No report was generated")
        print("Analysis completed but no report was generated.")


if __name__ == "__main__":
    main()