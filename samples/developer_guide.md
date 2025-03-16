# RepoGraph Developer Guide

Welcome to the RepoGraph Developer Guide! This document provides a comprehensive overview of how to work with the RepoGraph codebase. Whether you are analyzing a code repository, conducting security scans, generating architectural diagrams, or fixing code with LLM support, this guide will help you understand the system’s structure, configuration, and best practices. Let’s dive right in.

---

## 1. Executive Summary

RepoGraph is a Python-based application for performing in-depth analyses of code repositories. It leverages large language models (LLMs) in various workflows—such as code quality checks, security audits, peer reviews, architectural visualizations, and automated code fixes—to help teams maintain high standards for their software projects. 

Key highlights:

- Written entirely in Python (with virtual environment support recommended).
- Modular architecture comprising agents, workflows, and utilities.
- Configurable via JSON settings, environment variables, or .env files.
- High-level CLI interface (main.py) for running different analysis workflows.
- Extensible design: add new agents, plug in additional LLM providers, or customize workflows.

---

## 2. Architecture Overview

### 2.1 System Architecture

At a high level, RepoGraph follows a layered structure:

1. **CLI / Entry Points**  
   The application’s primary entry point is found in [main.py](../main.py). This script parses command-line arguments, initializes shared services (logging, config, LLM providers), and triggers desired workflows.

2. **Core Workflow Engine**  
   Workflows are constructed in [src/core/workflow.py](../src/core/workflow.py) using a “builder” pattern. A workflow orchestrates multiple agents, managed by the `Supervisor` class in [src/core/supervisor.py](../src/core/supervisor.py), which uses an LLM to decide agent order dynamically when required.

3. **Agents**  
   Agents perform distinct tasks (e.g., repository loading, file analysis, security scanning, code fixing). The [src/agents](../src/agents) package groups them by domain:  
   - repository/ (e.g., repository loading, QA)  
   - analysis/ (e.g., file analysis, report generation)  
   - security/ (e.g., critical method analysis, security scans)  
   - code_quality/ (e.g., peer review, code fix, test generation)  
   - visualization/ (e.g., architecture diagramming)

4. **Configuration**  
   Central configuration management is handled by [src/config/settings.py](../src/config/settings.py). Default settings are defined in [src/config/defaults.py](../src/config/defaults.py) and can be overridden by environment variables or a .env file.

5. **Models**  
   Data models (e.g., `Repository`, `FileInfo`, `RepositoryReport`, `Finding`, etc.) live under [src/models](../src/models). They encapsulate domain concepts like repository structure, analysis findings, and reporting elements.

6. **Utilities**  
   A set of utility modules in [src/utils](../src/utils) provides file handling, concurrency, logging, and security pattern matching.

If viewed as a diagram, you would see “main.py” at the top calling into “core” components, which in turn orchestrate various “agents,” each using “models” and “utils,” all configured by “config.”

### 2.2 Design Patterns

- **Factory Pattern**:  
  The `AgentFactory` in [src/core/agent_factory.py](../src/core/agent_factory.py) registers agent classes and creates agent instances dynamically.
- **Builder Pattern**:  
  The `WorkflowBuilder` in [src/core/workflow.py](../src/core/workflow.py) constructs predefined workflows (standard analysis, security analysis, etc.) or custom ones.
- **Supervisor / Orchestration Pattern**:  
  The `Supervisor` in [src/core/supervisor.py](../src/core/supervisor.py) uses an LLM to decide the next agent to run based on the current state and user queries.
- **Abstract Base Agent**:  
  All agents inherit from `Agent` in [src/core/agent_base.py](../src/core/agent_base.py), ensuring consistent method signatures (`invoke`) and logging utilities.

### 2.3 Data Flow

1. Users invoke RepoGraph via the command line (e.g., “python main.py --analysis standard …”).  
2. Configuration and logging are set up; relevant agents are prepared.  
3. The selected workflow orchestrates multiple agents:  
   - Repository scanning → File analysis → Security checks → Code or peer review → Reporting  
4. Agents may update a shared “state,” capturing partial analyses and enabling “Supervisor” to decide next steps.  
5. Results are written to disk or displayed in the console (reports, logs, etc.).

---

## 3. Core Components

Below is an overview of key modules and how they fit together. This section highlights only the most notable ones so you can easily navigate the codebase.

### 3.1 Configuration (src/config)

- **settings.py**  
  • Manages loading configuration from defaults, .env files, JSON files, or environment variables.  
  • Main class: `Config` → use `get(), set(), as_dict(), save_to_file()`.  
  • Example usage:  
    ```python
    from src.config.settings import Config

    config = Config()  # loads defaults + environment variables
    api_key = config.get("llm.openai.api_key")
    config.set("analysis.max_files", 200)
    ```
- **defaults.py**  
  • Houses `DEFAULT_CONFIG`, a nested dictionary of default settings (LLM providers, logging, etc.).  
  • If you add a new analysis feature, ensure you add default config entries here.

### 3.2 CLI / Main Application (main.py)

- **main.py**  
  • Entry point for RepoGraph.  
  • Uses `argparse` to parse subcommands for workflows:  
    - run_standard_analysis(args)  
    - run_security_analysis(args)  
    - run_code_fix(args)  
    - run_peer_review(args)  
  • Example usage:
    ```bash
    python main.py standard --repo_path /path/to/repo --config config.json
    ```
  • The “standard” subcommand then calls `run_standard_analysis(args)`, initializing the necessary agents from `WorkflowBuilder`.

### 3.3 Agents (src/agents)

Agents perform specialized tasks. Some highlights:

- **repository/loader.py** (`RepositoryLoaderAgent`)  
  • Scans a repository and populates the state with file info (paths, types, etc.). Example:
    ```python
    loader_agent = RepositoryLoaderAgent(model=some_llm_model)
    state = loader_agent.invoke(state)
    ```
- **analysis/file_analyzer.py** (`FileAnalyzerAgent`)  
  • Analyzes each file’s contents, generating descriptive summaries.  
  • Uses concurrency to speed up processing for large codebases.
- **analysis/report_generator.py** (`ReportGeneratorAgent`)  
  • Compiles a final, human-readable or JSON-based report summarizing findings.  
  • Typically runs toward the end of a workflow.
- **security/security_analyzer.py** (`SecurityAnalyzerAgent`)  
  • Scans for known security patterns and vulnerabilities. Merges results into a security report.  
- **code_quality/peer_review_agent.py** (`PeerReviewAgent`)  
  • Conducts a “peer review,” focusing on coding standards, readability, maintainability, and best practices.  
- **code_quality/code_fix_agent.py** (`CodeFixAgent`)  
  • Proposes code fixes for errors or issues, guided by logs or user queries.  
- **visualization/architecture_diagrammer.py** (`ArchitectureDiagramGeneratorAgent`)  
  • Utilizes an LLM to identify an application’s high-level architecture, data flow, and creates diagrams in Mermaid or a similar format.

### 3.4 Workflow System (src/core/workflow.py)

- **WorkflowBuilder**  
  • Central builder for orchestrating multi-agent workflows.  
  • Example:  
    ```python
    from src.core.workflow import WorkflowBuilder

    builder = WorkflowBuilder(config, llm_provider)
    workflow = builder.create_standard_workflow(repo_path)
    workflow.run()
    ```

### 3.5 LLM Integration (src/llm)

- **provider.py** (`LLMProvider`)  
  • Abstracts away multiple language model backends (OpenAI, Anthropic, local models).  
  • Usage example:
    ```python
    from src.llm.provider import LLMProvider

    llm_provider = LLMProvider(config)
    model = llm_provider.get_default_model()
    response = model.generate_text("Hello, LLM!")
    ```

### 3.6 Models (src/models)

- **repository.py**  
  • `Repository`, `FileInfo`, `DirectoryInfo` → Represent file structures, track file metadata and code hierarchy.
- **report.py**  
  • `RepositoryReport`, `ReportSection`, `DiagramInfo`, etc. → Classes for structuring final output (Markdown, HTML, JSON).  
- **findings.py**  
  • Defines data classes for security vulnerabilities, code smells, performance issues, best practice violations, etc.

### 3.7 Utilities (src/utils)

- **file_utils.py**  
  • Functions for listing files in a repo, applying `.gitignore`, reading file contents, checking for binary files, building a directory tree.
- **concurrency.py**  
  • Tools for parallel processing (`parallel_process_with_progress`), rate limiting (`rate_limited`), and retries.
- **logging_utils.py**  
  • `setup_logging`, `log_execution_time`, `StatusLogger` → Manage log levels, track function durations, progress metrics.  
- **security_patterns.py**  
  • Regex-based definitions of common security vulnerabilities (SQL injections, credential leaks, etc.).

---

## 4. Developer Workflows

### 4.1 Setup and Installation

1. **Clone the repository**  
   ```
   git clone https://github.com/your-org/RepoGraph.git
   cd RepoGraph
   ```
2. **Create and activate a virtual environment (recommended)**  
   ```bash
   python -m venv venv
   source venv/bin/activate  # Mac/Linux
   # or
   venv\Scripts\activate.bat  # Windows
   ```
3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure environment (optional)**  
   - Copy `.env.example` to `.env` and fill in your LLM API credentials (e.g., `OPENAI_API_KEY`).
   - Alternatively, define environment variables in your shell or specify a config JSON.

### 4.2 Build and Test

- **Build**  
  As a Python repo, there’s no formal “build” step, but you can create distribution packages if needed:
  ```bash
  python setup.py sdist bdist_wheel
  ```
- **Run Tests**  
  If a tests/ folder exists (not detailed here, but recommended), run:
  ```bash
  pytest --maxfail=1 --disable-warnings -v
  ```
  or use any relevant test command documented in your CI configuration.

### 4.3 Common Development Tasks

1. **Adding a New Agent**  
   - Create a new file `src/agents/[category]/my_new_agent.py`.  
   - Inherit from `Agent`:
     ```python
     from src.core.agent_base import Agent

     class MyNewAgent(Agent):
         def invoke(self, state):
             # your custom logic
             return state
     ```
   - Register it in `AgentFactory` (e.g., `__init__.py` or `AGENT_CLASSES` mapping).
   - Update `WorkflowBuilder` if you want the new agent included in an existing or custom workflow.

2. **Modifying Configuration**  
   - Add new default entries in `src/config/defaults.py`.
   - Validate new fields in `src/config/settings.py` with `_validate_config`.
   - Overwrite them via your `.env` or an external config JSON if needed.

3. **Integrating a New LLM Provider**  
   - Implement `_initialize_myprovider()` in `LLMProvider` and handle authentication or model loading logic.
   - Add a relevant key under `"llm"."providers"` in your default or user config.

4. **Creating a Custom Workflow**  
   - Extend `WorkflowBuilder` with a `create_my_custom_workflow()` method that loads specific agents in the order you want.
   - Or use a `Supervisor` directly if you want an LLM-based dynamic agent selection.

---

## 5. API Reference

While RepoGraph’s primary interface is through CLI workflows, below is a quick summary of key Python APIs frequently used by developers:

1. **Config Class (src/config/settings.py)**  
   - `Config(config_file=None, env_prefix=None)`
   - Methods: `get(key)`, `set(key, value)`, `save_to_file()`
2. **LLMProvider (src/llm/provider.py)**  
   - `LLMProvider(config)`
   - Methods: `add_model(provider_key, model_name)`, `get_model(model_name)`, `get_default_model()`
3. **AgentFactory (src/core/agent_factory.py)**  
   - `AgentFactory(llm_provider, config)`  
   - Methods: `register_agent(name, cls)`, `create_agent(name, **kwargs)`
4. **WorkflowBuilder (src/core/workflow.py)**  
   - `create_standard_workflow(repo_path)`, `create_security_workflow(repo_path)`, etc.
   - `run()` method to execute the workflow (returns a final state or report).

---

## 6. Best Practices and Conventions

1. **Coding Standards**  
   - Follow PEP 8 style guidelines. A linter (e.g., `flake8`) and formatter (`black`) are recommended.  
   - Use descriptive variable/function/agent names.  

2. **Logging**  
   - Use `setup_logging` at the start of scripts or workflows to ensure consistent logging.
   - Log important actions at INFO level (e.g., workflow steps) and details at DEBUG level (e.g., file-by-file analysis).

3. **Configuration**  
   - Keep secrets and API keys out of version control by using `.env` or environment variables.  
   - Validate new config fields with `_validate_config` to avoid runtime surprises.

4. **Agents**  
   - Each agent’s `invoke(state)` method should return the updated state. Keep state modifications minimal and well-documented.  
   - Provide meaningful logs or messages in `state["messages"]` so subsequent agents can interpret them.

5. **Performance**  
   - Use concurrency utilities (`parallel_map`, etc.) for CPU-bound tasks that do not conflict with each other.  
   - For large repositories, consider limiting the scope or chunking analyses to avoid timeouts or memory issues.

6. **Commit Messages**  
   - Use clear, concise commit messages referencing the task or issue ID if applicable (e.g., “Fix #123: Add concurrency for file analyzer”).

---

## 7. Troubleshooting and FAQs

1. **“Module not found” errors**  
   - Make sure you are running scripts from the repository root or have the root directory added to `PYTHONPATH`.  
   - Confirm your virtual environment is active and dependencies are installed.

2. **“LLM API key not found”**  
   - Check your environment variables or .env file. Confirm keys are spelled correctly in `Config`.  

3. **Poor performance on large repos**  
   - Increase concurrency or memory (adjust default concurrency in `src/utils/concurrency.py`).  
   - Filter certain file types (e.g., skip large media files) via `.gitignore` or agent-level checks.

4. **Agent “invoke” fails**  
   - Check the logs. Likely the `state` is missing a property this agent expects (e.g., no `repo_path`).  
   - Update preceding agents or ensure your custom workflow includes a repository loader step first.

5. **Report not generating**  
   - Ensure a `ReportGeneratorAgent` or equivalent agent runs at the end.  
   - Verify any required data is available in the `state` (e.g., file descriptions, security findings).

---

## 8. Glossary

- **Agent**: A class that inherits from `AgentBase` and has a defined `invoke(state)` method for performing a specific task.  
- **LLM (Large Language Model)**: A machine learning model capable of generating or analyzing text, e.g., OpenAI GPT.  
- **Workflow**: A sequence of agents, typically built by `WorkflowBuilder`, that accomplishes a higher-level analysis goal (e.g., security or peer review).  
- **State**: A shared data structure passed between agents to persist intermediate results (e.g., file lists, partial analysis logs).  
- **Supervisor**: A special controller that uses an LLM to decide which agent to invoke next, often used for dynamic or open-ended workflows.  
- **.env file**: A file containing environment variables (like API keys) for local development that are loaded at runtime but ignored by version control.

---

## Closing Note

We hope this Developer Guide clarifies how to navigate, extend, and maintain the RepoGraph project. Whether you are building new agents, embedding novel LLM providers, or refining security checks, RepoGraph’s modular design and abundant utilities make it straightforward to adapt to your needs.

For deeper questions or to propose major design changes, please open an issue or a discussion on the project’s repository. Happy coding and analyzing!

---

*Report generated: 2025-03-16 22:01:02*