# Repository Analyzer

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A modular, AI-powered multi-agent system for comprehensive code repository analysis, offering insights, improvements, and documentation for developer onboarding and code maintenance.

## 🌟 Features

- **Comprehensive Repository Analysis**: Understand complex codebases quickly and thoroughly
- **Security Vulnerability Detection**: Identify potential security issues with recommendations
- **Architecture Diagramming**: Generate visualizations of system architecture and data flows
- **Code Quality Assessment**: Get detailed peer reviews with actionable recommendations
- **Error Log Analysis**: Debug issues with targeted code fixes
- **Detailed Documentation**: Generate comprehensive developer guides
- **Interactive Q&A**: Ask questions about the codebase and get informed answers

## 📋 Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Analysis Workflow](#advanced-analysis-workflow)
  - [Peer Review](#peer-review)
  - [Security Analysis](#security-analysis)
  - [Code Fixes](#code-fixes)
  - [Q&A Mode](#qa-mode)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [CLI Commands](#cli-commands)
- [Extending](#extending)
- [Contributing](#contributing)
- [License](#license)

## 🔧 Installation

### Prerequisites

- Python 3.8 or higher
- OpenAI API key or Anthropic API key
- Also supports running with local LLMs to ensure privacy and reduce API costs


### Setup

1. Clone the repository
   ```bash
   git clone https://github.com/utkucgln/RepoGraph.git
   ```

2. Create a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
   
3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Set up your API keys
   ```bash
   # For OpenAI
   export OPENAI_API_KEY=your_api_key_here
   
   # For Anthropic
   export ANTHROPIC_API_KEY=your_api_key_here
   ```

## 🚀 Usage

### Advanced Analysis Workflow

The standard analysis workflow includes:

1. Repository loading and scanning
2. File analysis and understanding
3. Report generation
4. Architecture diagram creation
5. Critical method identification
6. Security vulnerability analysis

Each step builds on the previous, creating a comprehensive understanding of the codebase.

```bash
# Run with custom configuration
python -m main advanced --repo-path /path/to/repository --config /path/to/config.json
```
This will execute the full analysis workflow and generate reports in the reports directory.
The standard analysis workflow includes:

Repository loading and scanning
File analysis and understanding
Report generation
Architecture diagram creation
Critical method identification

Each step builds on the previous, creating a comprehensive understanding of the codebase.
### Peer Review

Perform a detailed peer review of code quality:

```bash
python -m main review --repo-path /path/to/repository
```

The peer review analyzes:
- Code organization and structure
- Code quality and readability
- Architecture and design patterns
- Performance considerations
- Security practices
- Testing coverage
- Documentation quality
- Maintainability factors
- Adherence to best practices

### Security Analysis

Focus specifically on security vulnerabilities:

```bash
python -m main security --repo-path /path/to/repository
```

This identifies:
- Authentication and authorization issues
- Input validation vulnerabilities
- Insecure data handling
- SQL injection risks
- XSS vulnerabilities
- Insecure dependencies
- Hardcoded secrets

### Code Fixes

Analyze error logs and get suggested fixes:

```bash
python -m main fix --repo-path /path/to/repository --logs /path/to/logs.txt
```

The tool will:
1. Analyze the error logs
2. Identify problematic files and lines
3. Generate targeted fixes
4. Provide implementation instructions

### Q&A Mode

Ask questions about the repository:

```bash
python -m main qa --repo-path /path/to/repository --query "How does the authentication system work?"
```

## 🏗️ Architecture

The Repository Analyzer uses a modular, agent-based architecture:

```
repository-analyzer/
├── src/
│   ├── agents/                 # Specialized analysis agents
│   │   ├── repository/         # Repository management
│   │   ├── analysis/           # Code analysis
│   │   ├── visualization/      # Diagram generation
│   │   ├── security/           # Security analysis
│   │   └── code_quality/       # Code review & fixes
│   ├── core/                   # Core framework
│   ├── llm/                    # LLM integration
│   ├── utils/                  # Utilities
│   ├── models/                 # Data models
│   ├── config/                 # Configuration
│   └── cli/                    # Command-line interface
├── examples/                   # Example scripts
└── tests/                      # Unit tests
```

The system employs these components:

- **Agents**: Specialized AI-powered modules that perform specific analysis tasks
- **Workflows**: Orchestrated sequences of agent activities
- **LLM Layer**: Abstraction for working with language models (OpenAI, Anthropic)
- **State Management**: System for tracking analysis state and sharing information between agents

## ⚙️ Configuration

The system can be configured through a JSON file:

```json
{
  "llm": {
    "provider": "openai",
    "default_model": "gpt-4o",
    "openai": {
      "api_key": null,
      "temperature": 0.0
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 20
    }
  },
  "analysis": {
    "max_workers": 10,
    "ignore_gitignore": true,
    "max_file_size": 10485760
  },
  "output": {
    "directory": "./reports",
    "report_format": "markdown"
  }
}
```

Key configuration options:
- LLM provider and model selection
- Rate limiting to manage API usage
- Worker pool size for parallel processing
- Output format and location

## 🖥️ CLI Commands

The system provides several command-line interface commands:

- `advanced`: Run a full repository analysis
- `review`: Perform a peer review
- `security`: Run a security analysis
- `fix`: Analyze logs and suggest fixes
- `qa`: Answer questions about the repository

Each command supports various options:

```bash
python -m main analyze --help
```

## 🔌 Extending

The modular architecture makes it easy to extend the system:

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.