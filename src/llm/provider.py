"""
LLM provider abstraction for repository analyzer.

This module provides a unified interface for interacting with different
language model providers (OpenAI, Anthropic, etc.).
"""

import os
import logging
from typing import Dict, Any, Optional, List


class LLMProvider:
    """Abstract interface for LLM providers.

    This class provides a common interface for working with different
    LLM providers, handling authentication, model selection, and invocation.
    """

    def __init__(self, provider_name: str = "openai", config: Optional[Dict[str, Any]] = None):
        """Initialize the LLM provider.

        Args:
            provider_name: Name of the LLM provider (openai, anthropic, etc.)
            config: Configuration for the provider (defaults to environment variables)
        """
        self.provider_name = provider_name.lower()
        self.config = config or {}
        self.logger = logging.getLogger(f"llm.{provider_name}")
        self.models = {}

        self._initialize_provider()

    def _initialize_provider(self) -> None:
        """Initialize the specified LLM provider.

        This method sets up the appropriate client based on the provider name.
        """
        if self.provider_name == "openai":
            self._initialize_openai()
        elif self.provider_name == "anthropic":
            self._initialize_anthropic()
        elif self.provider_name == "local":
            self._initialize_local()
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    def _initialize_openai(self) -> None:
        """Initialize the OpenAI provider."""
        try:
            from langchain_openai import ChatOpenAI, OpenAI

            # Get API key from config or environment
            api_key = self.config.get("api_key", os.getenv("OPENAI_API_KEY"))
            if not api_key:
                raise ValueError("OpenAI API key not found in config or environment")

            # Initialize default models
            self.models = {
                "gpt-4o": ChatOpenAI(model="gpt-4o", openai_api_key=api_key),
                "gpt-4o-mini": ChatOpenAI(model="gpt-4o-mini", openai_api_key=api_key),
                "o1": ChatOpenAI(model="o1", openai_api_key=api_key),
                "o3-mini": OpenAI(model="o3-mini", openai_api_key=api_key)
            }

            self.logger.info("OpenAI provider initialized successfully")
        except ImportError:
            self.logger.error("Failed to import OpenAI libraries")
            raise ImportError("langchain_openai library not found. Install with: pip install langchain-openai")

    def _initialize_anthropic(self) -> None:
        """Initialize the Anthropic provider."""
        try:
            from langchain_anthropic import ChatAnthropic

            # Get API key from config or environment
            api_key = self.config.get("api_key", os.getenv("ANTHROPIC_API_KEY"))
            if not api_key:
                raise ValueError("Anthropic API key not found in config or environment")

            # Initialize default models
            self.models = {
                "claude-3-opus": ChatAnthropic(model="claude-3-opus-latest", anthropic_api_key=api_key),
                "claude-3-5-sonnet": ChatAnthropic(model="claude-3-5-sonnet-latest", anthropic_api_key=api_key),
                "claude-3-7-sonnet": ChatAnthropic(model="claude-3-7-sonnet-latest", anthropic_api_key=api_key)
            }

            self.logger.info("Anthropic provider initialized successfully")
        except ImportError:
            self.logger.error("Failed to import Anthropic libraries")
            raise ImportError("langchain_anthropic library not found. Install with: pip install langchain-anthropic")

    def _initialize_local(self) -> None:
        """Initialize provider for local LLMs."""
        try:
            # Import libraries for local model support
            from llama_cpp import Llama
            from langchain_community.llms import LlamaCpp, HuggingFacePipeline

            # Get local model path from config
            model_path = self.config.get("model_path", os.getenv("LOCAL_LLM_PATH"))
            if not model_path:
                raise ValueError("Local model path not found in config or environment")

            # Initialize models based on their type
            model_type = self.config.get("model_type", "llama_cpp")

            if model_type == "llama_cpp":
                self.models = {
                    "local_default": LlamaCpp(
                        model_path=model_path,
                        n_ctx=self.config.get("context_length", 4096),
                        temperature=self.config.get("temperature", 0.0),
                        max_tokens=self.config.get("max_tokens", 4096),
                        verbose=False
                    )
                }
            elif model_type == "huggingface":
                import torch
                from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

                tokenizer = AutoTokenizer.from_pretrained(model_path)
                model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    torch_dtype=torch.float16,
                    low_cpu_mem_usage=True,
                    device_map="auto"
                )

                pipe = pipeline(
                    "text-generation",
                    model=model,
                    tokenizer=tokenizer,
                    max_new_tokens=self.config.get("max_tokens", 4096),
                    temperature=self.config.get("temperature", 0.0)
                )

                self.models = {
                    "local_default": HuggingFacePipeline(pipeline=pipe)
                }

            self.logger.info("Local LLM provider initialized successfully")
        except ImportError as e:
            self.logger.error(f"Failed to import libraries for local LLM support: {e}")
            raise ImportError(
                "Required libraries not found. Install with: pip install llama-cpp-python transformers torch")

    def get_model(self, model_name: str) -> Any:
        """Get a specific language model.

        Args:
            model_name: Name of the model to get

        Returns:
            The requested language model

        Raises:
            ValueError: If the model is not available
        """
        self.logger.info(f"Getting model: {model_name}")
        if model_name not in self.models:
            self.logger.error(f"Requested model not available: {model_name}")
            raise ValueError(f"Model not available: {model_name}")

        return self.models[model_name]

    def add_model(self, model_name: str, model_instance: Any) -> None:
        """Add a new model to the provider.

        Args:
            model_name: Name to use for the model
            model_instance: The model instance to add
        """
        self.models[model_name] = model_instance
        self.logger.info(f"Added model: {model_name}")

    def list_available_models(self) -> List[str]:
        """List all available models for this provider.

        Returns:
            List of available model names
        """
        return list(self.models.keys())

    def get_default_model(self) -> Any:
        """Get the default model for this provider.

        Returns:
            The default language model

        Raises:
            ValueError: If no models are available
        """
        if not self.models:
            raise ValueError(f"No models available for provider: {self.provider_name}")

        # Return the first model as default if not specified
        default_model_name = self.config.get("default_model")
        if default_model_name and default_model_name in self.models:
            return self.models[default_model_name]

        # Otherwise return the first model
        return next(iter(self.models.values()))