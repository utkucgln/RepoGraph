#!/usr/bin/env python3
"""
Unified Repository Analysis Tool

This script provides a consolidated interface for running various repository analysis
workflows including:
- Standard repository analysis
- Security-focused analysis
- Code fixing
- Peer review

All workflows use the same underlying framework but with specific configurations
for each analysis type.
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


def setup_common_components(args, log_file="logs/repository_analysis.log"):
    """Set up and return components needed by all workflows."""

    # Set up logging
    logger = setup_logging(
        log_level=args.log_level,
        log_file=log_file
    )

    # Create output directories
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    # Create configuration
    config = Config(args.config)

    # Override output directory in config if needed
    if args.output_dir:
        config.set(args.output_dir, "output", "directory")

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

    return logger, config, workflow_builder


def run_standard_analysis(args):
    """Run a standard repository analysis workflow."""

    logger, _, workflow_builder = setup_common_components(
        args,
        log_file=os.path.join(args.output_dir, "repository_analysis.log")
    )

    logger.info("Starting standard repository analysis")

    # Create and run a standard analysis workflow
    workflow = workflow_builder.create_standard_workflow()

    # Set up initial state with repository path
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": f"Please analyze the repository at the following Path: {args.repo_path}"
            }
        ],
        "repo_path": args.repo_path
    }

    # Run the workflow
    logger.info(f"Analyzing repository at: {args.repo_path}")
    final_state = workflow.run(initial_state)

    # Check if the report was generated
    report_message = None
    for message in final_state.get("messages", []):
        if getattr(message, "name", "") == "report" or message.get("name") == "report":
            report_message = message
            break

    if report_message:
        report_path = os.path.join(args.output_dir, "developer_guide.md")
        report_content = getattr(report_message, "content", None)
        if report_content is None:
            report_content = report_message.get("content", "")

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Report saved to: {report_path}")
        print(f"Analysis complete! Report saved to: {report_path}")
    else:
        logger.warning("No report was generated")
        print("Analysis completed but no report was generated.")


def run_security_analysis(args):
    """Run a security-focused repository analysis workflow."""

    logger, _, workflow_builder = setup_common_components(
        args,
        log_file=os.path.join(args.output_dir, "security_analysis.log")
    )

    logger.info("Starting security-focused repository analysis")

    # Create and run a security analysis workflow
    workflow = workflow_builder.create_security_workflow()

    # Set up initial state with repository path
    initial_state = {
        "messages": [
            {
                "role": "user",
                "content": f"Please perform a security analysis on the repository at the following Path: {args.repo_path}"
            }
        ],
        "repo_path": args.repo_path
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
        report_path = os.path.join(args.output_dir, "security_report.md")
        report_content = getattr(security_report, "content", None)
        if report_content is None:
            report_content = security_report.get("content", "")

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Security report saved to: {report_path}")
        print(f"Security analysis complete! Report saved to: {report_path}")
    else:
        logger.warning("No security report was generated")
        print("Security analysis completed but no report was generated.")


def run_code_fix(args):
    """Run a code fixing workflow."""

    logger, _, workflow_builder = setup_common_components(
        args,
        log_file=os.path.join(args.output_dir, "code_fix.log")
    )

    logger.info("Starting code fix workflow")

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
        report_path = os.path.join(args.output_dir, "code_fix_report.md")
        report_content = getattr(report_message, "content", None)
        if report_content is None:
            report_content = report_message.get("content", "")

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Check if there are any fixed files to save
        fixed_files = final_state.get("fixed_files", {})
        if fixed_files:
            fixes_dir = os.path.join(args.output_dir, "fixed_code")
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


def run_peer_review(args):
    """Run a peer review workflow."""

    logger, _, workflow_builder = setup_common_components(
        args,
        log_file=os.path.join(args.output_dir, "peer_review.log")
    )

    logger.info("Starting peer review workflow")

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

    if peer_review_message:
        report_path = os.path.join(args.output_dir, "peer_review_report.md")
        report_content = getattr(peer_review_message, "content", None)
        if report_content is None:
            report_content = peer_review_message.get("content", "")

        # Save the report to a file
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Peer review report saved to: {report_path}")
        print(f"Peer review complete! Report saved to: {report_path}")
    else:
        logger.warning("No peer review report was generated")
        print("Peer review completed but no report was generated.")


def main():
    """Parse command line arguments and run the specified workflow."""

    # Create the argument parser
    parser = argparse.ArgumentParser(
        description="Unified Repository Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run standard analysis
  python main.py standard --repo-path /path/to/repo

  # Run security analysis
  python main.py security --repo-path /path/to/repo

  # Run code fixing (all issue types)
  python main.py fix --repo-path /path/to/repo

  # Run code fixing (security issues only)
  python main.py fix --repo-path /path/to/repo --issue-type security

  # Run peer review
  python main.py review --repo-path /path/to/repo
"""
    )

    # Add subparsers for different commands
    subparsers = parser.add_subparsers(title="commands", dest="command", required=True)

    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--repo-path", type=str, required=True,
                               help="Path to the repository to analyze")
    common_parser.add_argument("--config", type=str, help="Path to a configuration file")
    common_parser.add_argument("--output-dir", type=str, default="reports",
                               help="Directory to save reports in")
    common_parser.add_argument("--log-level", type=str, default="INFO",
                               help="Logging level (DEBUG, INFO, WARNING, ERROR)")

    # Standard analysis command
    standard_parser = subparsers.add_parser("advanced", parents=[common_parser],
                                            help="Run advanced repository analysis")

    # Security analysis command
    security_parser = subparsers.add_parser("security", parents=[common_parser],
                                            help="Run security-focused repository analysis")

    # Code fix command
    fix_parser = subparsers.add_parser("fix", parents=[common_parser],
                                       help="Run code fixing workflow")
    fix_parser.add_argument("--target-file", type=str,
                            help="Specific file to fix (optional)")
    fix_parser.add_argument("--issue-type", type=str, default="all",
                            choices=["bugs", "performance", "security", "all"],
                            help="Type of issues to fix")

    # Peer review command
    review_parser = subparsers.add_parser("review", parents=[common_parser],
                                          help="Run peer review workflow")

    # Parse the arguments
    args = parser.parse_args()

    # Run the appropriate workflow
    if args.command == "advanced":
        run_standard_analysis(args)
    elif args.command == "security":
        run_security_analysis(args)
    elif args.command == "fix":
        run_code_fix(args)
    elif args.command == "review":
        run_peer_review(args)


if __name__ == "__main__":
    main()