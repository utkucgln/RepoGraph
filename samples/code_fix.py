"""
Code fix example.

This example demonstrates how to set up and run a code fixing workflow
that identifies and fixes issues in a codebase using AI agents.
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
    """Run a code fixing workflow."""
    # Set up logging
    logger = setup_logging(
        log_level="INFO",
        log_file="code_fix.log"
    )
    logger.info("Starting code fix workflow")

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Code Fixer")
    parser.add_argument("--repo-path", type=str, default=".", help="Path to the repository to fix")
    parser.add_argument("--target-file", type=str, help="Specific file to fix (optional)")
    parser.add_argument("--config", type=str, help="Path to a configuration file")
    parser.add_argument("--issue-type", type=str, default="all", 
                        choices=["bugs", "performance", "security", "all"],
                        help="Type of issues to fix")
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

    # Create and run a code fixing workflow
    workflow = workflow_builder.create_code_fix_workflow()

    # Set up initial state with repository path and target file
    target_path = args.target_file if args.target_file else "entire repository"
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": (
                    f"Please analyze and fix code issues in the {target_path} "
                    f"at the following path: {args.repo_path}. "
                    f"Focus on {args.issue_type} issues."
                )
            }
        ],
        "repo_path": args.repo_path,
        "target_file": args.target_file,
        "issue_type": args.issue_type
    }

    # Run the workflow
    logger.info(f"Analyzing and fixing code at: {args.repo_path}")
    if args.target_file:
        logger.info(f"Focusing on file: {args.target_file}")
    logger.info(f"Looking for issue types: {args.issue_type}")
    
    final_state = workflow.run(initial_state)

    # Print completion message
    logger.info("Code fix workflow complete")

    # Check if the report was generated
    report_message = None
    for message in final_state.get("messages", []):
        if getattr(message, "name", "") == "fix_report" or message.get("name") == "fix_report":
            report_message = message
            break

    if report_message:
        report_path = "reports/code_fix_report.md"
        report_content = getattr(report_message, "content", None)
        if report_content is None:
            report_content = report_message.get("content", "")

        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Check if there are any fixed files to save
        fixed_files = final_state.get("fixed_files", {})
        if fixed_files:
            fixes_dir = "reports/fixed_code"
            os.makedirs(fixes_dir, exist_ok=True)
            
            for file_path, content in fixed_files.items():
                # Create directory structure if needed
                file_save_path = os.path.join(fixes_dir, file_path)
                os.makedirs(os.path.dirname(file_save_path), exist_ok=True)
                
                # Save the fixed file
                with open(file_save_path, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"Fixed file saved to: {file_save_path}")

        logger.info(f"Fix report saved to: {report_path}")
        print(f"Code fix complete! Report saved to: {report_path}")
    else:
        logger.warning("No fix report was generated")
        print("Code fix completed but no report was generated.")


if __name__ == "__main__":
    main()
