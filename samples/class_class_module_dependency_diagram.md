# Class/Module Dependency Diagram

MainApp is the entry point that uses a Config object to manage configuration and leverages a WorkflowBuilder to initiate a workflow for different analysis types (standard, security, code fix, and peer review). WorkflowBuilder, in turn, uses both an AgentFactory (to instantiate the necessary agents) and a Supervisor (to coordinate the overall process). The Supervisor orchestrates the flow of operations among various Agents, reads and writes data from a Repository (which contains multiple FileInfo objects representing individual files), and ultimately compiles findings into a RepositoryReport.

Agent is defined as an abstract class whose concrete subclasses (RepositoryLoaderAgent, FileAnalyzerAgent, SecurityAnalyzerAgent, PeerReviewAgent, CodeFixAgent, and ArchitectureDiagramGeneratorAgent) each implement their own invoke method for specialized tasks. AgentFactory is responsible for creating these specific Agents upon request by registering their classes and creating instances when needed. Meanwhile, the Repository aggregates multiple FileInfo objects, and the RepositoryReport holds multiple Finding objects, further illustrating the composition relationships within the system.

```mermaid
classDiagram

    class MainApp {
        +run_standard_analysis(args)
        +run_security_analysis(args)
        +run_code_fix(args)
        +run_peer_review(args)
    }

    class Config {
        +get(key)
        +set(key, value)
        +as_dict()
        +save_to_file(path)
    }

    class WorkflowBuilder {
        +build_standard()
        +build_security()
        +build_custom()
    }

    class Supervisor {
        +decide_next_agent(state)
        +run_agents(state)
    }

    class Agent {
        <<abstract>>
        +invoke(state)
    }

    class AgentFactory {
        +register_agent(agent_name, agent_class)
        +create_agent(agent_name)
    }

    class RepositoryLoaderAgent {
        +invoke(state)
    }

    class FileAnalyzerAgent {
        +invoke(state)
    }

    class SecurityAnalyzerAgent {
        +invoke(state)
    }

    class PeerReviewAgent {
        +invoke(state)
    }

    class CodeFixAgent {
        +invoke(state)
    }

    class ArchitectureDiagramGeneratorAgent {
        +invoke(state)
    }

    class Repository {
        +files: List<FileInfo>
    }

    class FileInfo {
        +path: str
        +content: str
    }

    class RepositoryReport {
        +findings: List<Finding>
    }

    class Finding {
        +type: str
        +message: str
    }

    %% Relationships %%

    MainApp --> Config : "uses"
    MainApp --> WorkflowBuilder : "initiates workflow"

    WorkflowBuilder --> AgentFactory : "creates agents"
    WorkflowBuilder --> Supervisor : "manages"

    Supervisor --> Agent : "orchestrates"
    Supervisor --> Repository : "reads/writes data"
    Supervisor --> RepositoryReport : "compiles findings"

    AgentFactory --> Agent : "instantiates"

    Agent <|-- RepositoryLoaderAgent
    Agent <|-- FileAnalyzerAgent
    Agent <|-- SecurityAnalyzerAgent
    Agent <|-- PeerReviewAgent
    Agent <|-- CodeFixAgent
    Agent <|-- ArchitectureDiagramGeneratorAgent

    Repository o-- FileInfo : "aggregates multiple files"
    RepositoryReport o-- Finding : "contains many findings"
```
