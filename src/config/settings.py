"""
Configuration settings for repository analyzer.

This module provides functionality for loading, validating, and
accessing configuration settings for the repository analyzer.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from src.config.defaults import DEFAULT_CONFIG

logger = logging.getLogger("config.settings")


class Config:
    """Configuration management for repository analyzer.

    This class handles loading configuration from various sources,
    applying defaults, and providing access to configuration values.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.

        Args:
            config_path: Optional path to a config file (.json or .env)
        """
        self.config = DEFAULT_CONFIG.copy()

        # Load config from file if specified
        if config_path:
            self._load_from_file(config_path)

        # Override with environment variables
        self._load_from_env()

        # Validate the configuration
        self._validate_config()

        logger.info("Configuration loaded successfully")

    def _load_from_file(self, config_path: str) -> None:
        """Load configuration from a file.

        Args:
            config_path: Path to the configuration file
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return

        if path.suffix.lower() == '.json':
            try:
                with open(path, 'r') as f:
                    file_config = json.load(f)
                self._merge_config(file_config)
                logger.info(f"Loaded configuration from JSON file: {config_path}")
            except Exception as e:
                logger.error(f"Error loading JSON config file: {str(e)}")

        elif path.suffix.lower() == '.env':
            try:
                self._load_from_dotenv(path)
                logger.info(f"Loaded configuration from .env file: {config_path}")
            except Exception as e:
                logger.error(f"Error loading .env config file: {str(e)}")

        else:
            logger.warning(f"Unsupported config file format: {path.suffix}")

    def _load_from_dotenv(self, env_path: Path) -> None:
        """Load configuration from a .env file.

        Args:
            env_path: Path to the .env file
        """
        try:
            # Try to use python-dotenv if available
            from dotenv import load_dotenv
            load_dotenv(env_path)
            logger.info(f"Loaded environment variables from {env_path}")
        except ImportError:
            # Fall back to manual parsing
            logger.warning("python-dotenv not installed, parsing .env file manually")
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Define mappings from environment variables to config keys
        env_mappings = {
            # LLM provider settings
            "REPOSITORY_ANALYZER_LLM_PROVIDER": ["llm", "provider"],
            "OPENAI_API_KEY": ["llm", "openai", "api_key"],
            "ANTHROPIC_API_KEY": ["llm", "anthropic", "api_key"],
            "REPOSITORY_ANALYZER_DEFAULT_MODEL": ["llm", "default_model"],

            # Analysis settings
            "REPOSITORY_ANALYZER_MAX_WORKERS": ["analysis", "max_workers"],
            "REPOSITORY_ANALYZER_LOG_LEVEL": ["logging", "level"],
            "REPOSITORY_ANALYZER_IGNORE_GITIGNORE": ["analysis", "ignore_gitignore"],
            "REPOSITORY_ANALYZER_MAX_FILE_SIZE": ["analysis", "max_file_size"],

            # Output settings
            "REPOSITORY_ANALYZER_OUTPUT_DIR": ["output", "directory"],
            "REPOSITORY_ANALYZER_REPORT_FORMAT": ["output", "report_format"]
        }

        # Process environment variables
        for env_var, config_path in env_mappings.items():
            if env_var in os.environ:
                self._set_nested_value(self.config, config_path, os.environ[env_var])

    def _merge_config(self, config_to_merge: Dict[str, Any]) -> None:
        """Merge a config dictionary into the current config.

        Args:
            config_to_merge: Configuration dict to merge
        """

        def merge_dicts(target, source):
            for key, value in source.items():
                if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                    merge_dicts(target[key], value)
                else:
                    target[key] = value

        merge_dicts(self.config, config_to_merge)

    def _set_nested_value(self, target: Dict[str, Any], key_path: list, value: Any) -> None:
        """Set a value in a nested dictionary using a key path.

        Args:
            target: Target dictionary
            key_path: List of keys representing the path
            value: Value to set
        """
        # Convert value to appropriate type
        if isinstance(value, str):
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                value = float(value)

        # Navigate to the target location
        current = target
        for key in key_path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        # Set the value
        current[key_path[-1]] = value

    def _validate_config(self) -> None:
        """Validate the configuration."""
        # Check for required values
        if "llm" not in self.config:
            logger.warning("No LLM configuration specified, using defaults")
            self.config["llm"] = DEFAULT_CONFIG.get("llm", {})

        # Ensure LLM provider is specified
        if "provider" not in self.config.get("llm", {}):
            provider = "openai"  # Default provider
            logger.warning(f"No LLM provider specified, using default: {provider}")
            self.config.setdefault("llm", {})["provider"] = provider

        # Check for API keys
        provider = self.config["llm"]["provider"]
        if provider == "openai" and "api_key" not in self.config.get("llm", {}).get("openai", {}):
            logger.warning("No OpenAI API key specified")

        if provider == "anthropic" and "api_key" not in self.config.get("llm", {}).get("anthropic", {}):
            logger.warning("No Anthropic API key specified")

        # Validate max_workers
        max_workers = self.config.get("analysis", {}).get("max_workers", 10)
        if not isinstance(max_workers, int) or max_workers < 1:
            logger.warning(f"Invalid max_workers value: {max_workers}, using default: 10")
            self.config.setdefault("analysis", {})["max_workers"] = 10

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            *keys: Key path to the configuration value
            default: Default value if not found

        Returns:
            Configuration value, or default if not found
        """
        value = self.config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, value: Any, *keys: str) -> None:
        """Set a configuration value.

        Args:
            value: Value to set
            *keys: Key path to the configuration value
        """
        if not keys:
            raise ValueError("No keys specified")

        target = self.config
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]

        target[keys[-1]] = value

    def as_dict(self) -> Dict[str, Any]:
        """Get the full configuration as a dictionary.

        Returns:
            Configuration dictionary
        """
        return self.config.copy()

    def save_to_file(self, file_path: str) -> None:
        """Save the current configuration to a file.

        Args:
            file_path: Path to save the configuration to
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving configuration to {file_path}: {str(e)}")