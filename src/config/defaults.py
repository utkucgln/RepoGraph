"""
Default configuration settings for repository analyzer.

This module provides default configuration values for all
components of the repository analyzer system.
"""

# Default configuration for the repository analyzer
DEFAULT_CONFIG = {
    # LLM provider configuration
    "llm": {
        # Default provider (openai or anthropic)
        "provider": "openai",

        # Default model to use (falls back to provider-specific default if not set)
        "default_model": "gpt-4o",

        # OpenAI-specific settings
        "openai": {
            "api_key": None,  # Should be set via env var or config file
            "models": {
                "default": "gpt-4o",
                "lightweight": "gpt-4o-mini",
                "advanced": "o1"
            },
            "temperature": 0.0,  # Low temperature for deterministic responses
            "timeout": 120,  # Timeout in seconds
            "max_tokens": 4096  # Maximum response tokens
        },

        # Anthropic-specific settings
        "anthropic": {
            "api_key": None,  # Should be set via env var or config file
            "models": {
                "default": "claude-3-sonnet",
                "lightweight": "claude-3-haiku",
                "advanced": "claude-3-opus"
            },
            "temperature": 0.0,  # Low temperature for deterministic responses
            "timeout": 120,  # Timeout in seconds
            "max_tokens": 4096  # Maximum response tokens
        },

        "local": {
            "model_path": None,  # Should be set via env var or config file
            "model_type": "llama_cpp",  # or "huggingface"
            "context_length": 4096,
            "temperature": 0.0,
            "max_tokens": 4096,
            "models": {
                "default": "local_default"
            }
        },

        # Rate limiting to avoid API quota issues
        "rate_limit": {
            "enabled": True,
            "requests_per_minute": 20
        }
    },

    # Analysis settings
    "analysis": {
        # Maximum number of parallel workers
        "max_workers": 10,

        # Whether to respect .gitignore rules
        "ignore_gitignore": False,

        # Skip files larger than this size (in bytes)
        "max_file_size": 10 * 1024 * 1024,  # 10 MB

        # File patterns to always ignore (regex)
        "ignore_patterns": [
            r"\.git/",
            r"node_modules/",
            r"__pycache__/",
            r"\.venv/",
            r"\.pytest_cache/",
            r"\.mypy_cache/",
            r"\.tox/",
            r"\.eggs/",
            r"\.cache/",
            r"\.idea/",
            r"\.vscode/",
            r"\.DS_Store"
        ],

        # Security analysis settings
        "security": {
            "enabled": True,
            "scan_dependencies": True,
            "check_for_outdated": True
        },

        # Code quality settings
        "code_quality": {
            "enabled": True,
            "max_complexity": 10,
            "min_comments_ratio": 0.1
        }
    },

    # Agent-specific settings
    "agents": {
        "repository_loader": {
            "model_name": "gpt-4o-mini",  # Lightweight model for simple tasks
            "max_files": 1000  # Maximum number of files to load
        },
        "file_analyzer": {
            "model_name": "gpt-4o",  # More capable model for analysis
            "max_file_size": 10 * 1024 * 1024  # 10 MB limit for file analysis
        },
        "report_generator": {
            "model_name": "o1",  # High-quality report generation
            "report_sections": [
                "executive_summary",
                "architecture_overview",
                "core_components",
                "code_quality",
                "security_considerations",
                "recommendations"
            ]
        },
        "architecture_diagram_generator": {
            "model_name": "o1",
            "diagrams": [
                "component",
                "sequence",
                "class"
            ]
        },
        "critical_method_analyzer": {
            "model_name": "gpt-4o",
            "method_categories": [
                "authentication",
                "authorization",
                "data_validation",
                "file_operations",
                "network_operations"
            ]
        },
        "security_agent": {
            "model_name": "gpt-4o",
            "vulnerability_categories": [
                "injection",
                "authentication",
                "sensitive_data",
                "security_misconfiguration",
                "insecure_components"
            ]
        },
        "code_fix_agent": {
            "model_name": "gpt-4o",
            "max_fixes": 10
        },
        "peer_review_agent": {
            "model_name": "gpt-4o",
            "review_depth": "comprehensive"
        },
        "repository_qa_agent": {
            "model_name": "gpt-4o"
        }
    },

    # Output settings
    "output": {
        "directory": "./reports",
        "report_format": "markdown",
        "create_summary": True,
        "include_diagrams": True
    },

    # Logging settings
    "logging": {
        "level": "INFO",
        "file": None,  # None for console only, otherwise path to log file
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    },

    # Cache settings
    "cache": {
        "enabled": True,
        "directory": "./.cache",
        "ttl": 24 * 60 * 60  # Time-to-live in seconds (24 hours)
    }
}