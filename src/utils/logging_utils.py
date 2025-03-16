"""
Logging utilities for repository analyzer.

This module provides functions for setting up and configuring logging
for the repository analyzer system.
"""

import os
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any


def setup_logging(log_level: str = "INFO",
                  log_file: Optional[str] = None,
                  log_format: Optional[str] = None) -> logging.Logger:
    """Set up logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path to write logs to
        log_format: Optional custom log format

    Returns:
        Configured root logger
    """
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Define log format if not specified
    if log_format is None:
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers if any
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Create file handler if specified
    if log_file:
        # Create the directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.

    Args:
        name: Name of the logger

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_execution_time(func):
    """Decorator to log execution time of functions.

    Args:
        func: The function to decorate

    Returns:
        Wrapped function that logs execution time
    """

    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        start_time = datetime.now()
        logger.debug(f"Starting {func.__name__}...")

        try:
            result = func(*args, **kwargs)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            logger.debug(f"Completed {func.__name__} in {duration:.2f} seconds")

            return result
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            logger.error(f"Failed {func.__name__} after {duration:.2f} seconds: {str(e)}")
            raise

    return wrapper


def log_state_changes(before_state: Dict[str, Any], after_state: Dict[str, Any]) -> None:
    """Log changes made to the state by an agent.

    Args:
        before_state: State before agent execution
        after_state: State after agent execution
    """
    logger = logging.getLogger("state")

    # Log new messages
    before_messages = before_state.get("messages", [])
    after_messages = after_state.get("messages", [])

    new_message_count = len(after_messages) - len(before_messages)
    if new_message_count > 0:
        logger.debug(f"Added {new_message_count} new messages to state")
        for i in range(len(before_messages), len(after_messages)):
            message = after_messages[i]
            role = message.get("role", "unknown")
            name = message.get("name", "unnamed")
            content_preview = str(message.get("content", ""))[:50]
            if len(content_preview) == 50:
                content_preview += "..."

            logger.debug(f"New message - Role: {role}, Name: {name}, Content: {content_preview}")

    # Log new completed stages
    before_stages = before_state.get("completed_stages", [])
    after_stages = after_state.get("completed_stages", [])

    new_stages = [stage for stage in after_stages if stage not in before_stages]
    if new_stages:
        logger.debug(f"Completed new stages: {', '.join(new_stages)}")


class StatusLogger:
    """Status logger for long-running processes.

    This class provides methods for logging status updates and progress
    during long-running operations.
    """

    def __init__(self, total_items: int = 0, name: str = "task"):
        """Initialize the status logger.

        Args:
            total_items: Total number of items to process
            name: Name of the task
        """
        self.total = total_items
        self.current = 0
        self.name = name
        self.logger = logging.getLogger(f"status.{name}")
        self.start_time = datetime.now()

        if total_items > 0:
            self.logger.info(f"Starting {name} with {total_items} items")

    def update(self, current: int, message: Optional[str] = None) -> None:
        """Update the progress status.

        Args:
            current: Current number of items processed
            message: Optional status message
        """
        self.current = current

        # Calculate progress percentage
        if self.total > 0:
            percentage = (current / self.total) * 100
            elapsed = (datetime.now() - self.start_time).total_seconds()

            # Estimate remaining time
            if current > 0:
                items_per_second = current / elapsed
                remaining_items = self.total - current
                eta_seconds = remaining_items / items_per_second if items_per_second > 0 else 0

                # Format the message
                status = f"{current}/{self.total} ({percentage:.1f}%) - ETA: {eta_seconds:.1f}s"
            else:
                status = f"{current}/{self.total} ({percentage:.1f}%)"

            if message:
                status = f"{status} - {message}"

            self.logger.info(status)
        elif message:
            self.logger.info(f"{current} items - {message}")

    def increment(self, amount: int = 1, message: Optional[str] = None) -> None:
        """Increment the current count.

        Args:
            amount: Amount to increment by
            message: Optional status message
        """
        self.update(self.current + amount, message)

    def complete(self, message: Optional[str] = None) -> None:
        """Mark the task as complete.

        Args:
            message: Optional completion message
        """
        elapsed = (datetime.now() - self.start_time).total_seconds()

        if message:
            self.logger.info(f"Completed {self.name} in {elapsed:.2f}s - {message}")
        else:
            self.logger.info(f"Completed {self.name} in {elapsed:.2f}s")