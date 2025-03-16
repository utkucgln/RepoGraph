"""
Architecture diagram generator agent.

This module provides an agent that creates architecture and data flow
diagrams based on repository analysis.
"""

import os
import re
import logging
import json
from typing import Dict, Any, List, Optional, Tuple

from src.core.agent_base import Agent
from src.utils.logging_utils import log_execution_time
from src.llm.response_parser import ResponseParser
from src.models.report import RepositoryReport, DiagramInfo


class ArchitectureDiagramGeneratorAgent(Agent):
    """Agent for generating architectural and data flow diagrams.

    This agent creates visual representations of system architecture,
    data flows, and component relationships.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the architecture diagram generator agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)
        self.parser = ResponseParser()

    @log_execution_time
    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and generate architectural diagrams.

        Args:
            state: Current state containing repository analysis

        Returns:
            Updated state with architecture diagrams
        """
        self.log_info("Architecture Diagram Generator: Starting diagram generation")

        # Check if repository report is available
        report_content = self._get_report_content(state)
        if not report_content:
            self.log_error("Architecture Diagram Generator: No report found in state")
            error_msg = "No repository report found. Report generator must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get file descriptions if available
        file_descriptions = self._get_file_descriptions(state)

        # Identify components based on the report and file descriptions
        components = self._identify_components(report_content, file_descriptions)

        # Generate diagrams
        diagrams = self._generate_diagrams(report_content, components, state)

        # Format diagrams and add to state
        diagrams_report = self._format_diagrams_report(diagrams)
        state = self.add_message_to_state(
            state,
            diagrams_report,
            "system",
            "architecture_diagrams"
        )

        # Update report object if available
        report_obj = state.get("report")
        if report_obj and isinstance(report_obj, RepositoryReport):
            for diagram in diagrams:
                diagram_info = DiagramInfo(
                    title=diagram["title"],
                    type=diagram["type"],
                    content=diagram["content"],
                    description=diagram.get("description", "")
                )
                report_obj.add_diagram(diagram_info)

        # Save diagrams to files if output directory exists
        output_dir = "reports/diagrams"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        for i, diagram in enumerate(diagrams):
            diagram_type = diagram["type"]
            title = re.sub(r'[^a-zA-Z0-9]', '_', diagram["title"].lower())
            diagram_path = os.path.join(output_dir, f"{diagram_type}_{title}.md")

            with open(diagram_path, "w", encoding="utf-8") as f:
                f.write(f"# {diagram['title']}\n\n")
                if "description" in diagram:
                    f.write(f"{diagram['description']}\n\n")
                f.write(f"```mermaid\n{diagram['content']}\n```\n")

            self.log_info(f"Diagram saved to {diagram_path}")

        # Mark this stage as complete
        if "completed_stages" not in state:
            state["completed_stages"] = []
        if self.name not in state["completed_stages"]:
            state["completed_stages"].append(self.name)

        self.log_info("Architecture Diagram Generator: Diagram generation complete")
        return state

    def _get_report_content(self, state: Dict[str, Any]) -> Optional[str]:
        """Get report content from state.

        Args:
            state: Current state

        Returns:
            Report content if found, None otherwise
        """
        # Try to get from report message
        report_message = self.get_last_message_by_name(state, "report")
        if report_message:
            return report_message.get("content", "")

        # Try to get from report object
        report_obj = state.get("report")
        if report_obj and hasattr(report_obj, "get_markdown"):
            return report_obj.get_markdown()

        return None

    def _get_file_descriptions(self, state: Dict[str, Any]) -> Optional[str]:
        """Get file descriptions from state.

        Args:
            state: Current state

        Returns:
            File descriptions if found, None otherwise
        """
        # Try to get from file_descriptions message
        file_descriptions_message = self.get_last_message_by_name(state, "file_descriptions")
        if file_descriptions_message:
            content = file_descriptions_message.get("content", "")
            if content and "File Descriptions:" in content:
                return content.split("File Descriptions:")[1].strip()
            return content

        return None

    def _identify_components(self, report_content: str,
                             file_descriptions: Optional[str] = None) -> List[Dict[str, Any]]:
        """Identify architectural components from report and file descriptions.

        Args:
            report_content: Repository report content
            file_descriptions: Optional file descriptions

        Returns:
            List of component dictionaries
        """
        self.log_info("Identifying architectural components")

        # Create prompt for component identification
        prompt = f"""
        Based on the repository analysis report, identify the main architectural components of the system.
        For each component, provide:
        1. Component name
        2. Component type (service, module, class, function, etc.)
        3. Key responsibilities
        4. Files/modules that implement this component
        5. Components it depends on
        6. Components that depend on it

        Repository Report:
        {report_content[:10000]}  # Limit to first 10,000 characters for prompt size
        """

        if file_descriptions:
            prompt += f"\n\nFile Descriptions:\n{file_descriptions[:5000]}"  # Add limited file descriptions

        prompt += """
        Format your response as a JSON array of component objects, like this example:
        [
          {
            "name": "AuthService",
            "type": "service",
            "responsibilities": ["User authentication", "Session management"],
            "files": ["auth.py", "session.py"],
            "depends_on": ["UserRepository", "ConfigService"],
            "depended_by": ["ApiController", "WebController"]
          },
          {
            "name": "UserRepository",
            "type": "repository",
            "responsibilities": ["User data storage", "User queries"],
            "files": ["user_repo.py", "models/user.py"],
            "depends_on": ["DatabaseService"],
            "depended_by": ["AuthService", "UserService"]
          }
        ]

        Provide only the JSON array, no other text.
        """

        # Get components from LLM
        self.log_info("Invoking LLM for component identification")
        response = self.model.invoke([{"role": "system", "content": prompt}])

        # Extract JSON components
        components = self.parser.extract_json(response.content)

        if not components or not isinstance(components, list):
            self.log_warning("Failed to extract components from LLM response")
            # Create a minimal default component
            components = [{
                "name": "System",
                "type": "system",
                "responsibilities": ["Main system functionality"],
                "files": [],
                "depends_on": [],
                "depended_by": []
            }]

        self.log_info(f"Identified {len(components)} components")
        return components

    def _generate_diagrams(self, report_content: str,
                           components: List[Dict[str, Any]],
                           state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate architecture and data flow diagrams.

        Args:
            report_content: Repository report content
            components: Identified components
            state: Current state

        Returns:
            List of diagram dictionaries
        """
        diagrams = []

        # 1. Generate System Architecture Diagram
        system_diagram = self._generate_system_architecture_diagram(components)
        if system_diagram:
            diagrams.append(system_diagram)

        # 2. Generate Data Flow Diagram
        data_flow_diagram = self._generate_data_flow_diagram(components, report_content)
        if data_flow_diagram:
            diagrams.append(data_flow_diagram)

        # 3. Generate Class/Module Dependency Diagram
        class_diagram = self._generate_class_diagram(components, report_content)
        if class_diagram:
            diagrams.append(class_diagram)

        # 4. Generate Sequence Diagrams for key processes
        sequence_diagrams = self._generate_sequence_diagrams(components, report_content)
        diagrams.extend(sequence_diagrams)

        return diagrams

    def _generate_system_architecture_diagram(self,
                                              components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a system architecture diagram.

        Args:
            components: Identified components

        Returns:
            Diagram dictionary or None if generation failed
        """
        self.log_info("Generating system architecture diagram")

        # Create prompt for system architecture diagram
        prompt = f"""
        Create a Mermaid component diagram that visualizes the system architecture based on the following components.
        Include all major components and their relationships.

        Components:
        {json.dumps(components, indent=2)}

        Generate only the Mermaid diagram code in the format:
        ```mermaid
        graph TD
            A[Component A] --> B[Component B]
            ...
        ```

        Use appropriate shapes and styles for different component types.
        Keep the diagram clean and readable.
        """

        # Get diagram from LLM
        response = self.model.invoke([{"role": "system", "content": prompt}])

        # Extract Mermaid diagram code
        mermaid_code = self.parser.extract_mermaid_diagram(response.content)

        if not mermaid_code:
            self.log_warning("Failed to extract system architecture diagram code")
            return None

        # Get description for the diagram
        description_prompt = f"""
        Provide a brief (2-3 paragraphs) description of the system architecture shown in this diagram.
        Explain the purpose of each component and how they interact with each other.

        Components:
        {json.dumps(components, indent=2)}

        Mermaid Diagram:
        {mermaid_code}
        """

        description_response = self.model.invoke([{"role": "system", "content": description_prompt}])

        return {
            "title": "System Architecture",
            "type": "component",
            "content": mermaid_code,
            "description": description_response.content
        }

    def _generate_data_flow_diagram(self, components: List[Dict[str, Any]],
                                    report_content: str) -> Dict[str, Any]:
        """Generate a data flow diagram.

        Args:
            components: Identified components
            report_content: Repository report content

        Returns:
            Diagram dictionary or None if generation failed
        """
        self.log_info("Generating data flow diagram")

        # Extract data flows from the report
        data_flows_prompt = f"""
        Based on the repository report and components, identify the key data flows in the system.
        For each data flow, describe:
        1. Source component
        2. Destination component
        3. Type of data being transferred
        4. Any transformations or validations applied

        Repository Report:
        {report_content[:7500]}

        Components:
        {json.dumps(components, indent=2)}

        Format your response as a JSON array of data flow objects, like this:
        [
          {{
            "source": "UserInterface",
            "destination": "AuthService",
            "data_type": "Credentials",
            "description": "User login credentials for authentication"
          }},
          {{
            "source": "AuthService",
            "destination": "UserRepository",
            "data_type": "UserID",
            "description": "User ID for fetching user profile"
          }}
        ]

        Provide only the JSON array, no other text.
        """

        # Get data flows from LLM
        data_flows_response = self.model.invoke([{"role": "system", "content": data_flows_prompt}])

        # Extract JSON data flows
        data_flows = self.parser.extract_json(data_flows_response.content)

        if not data_flows or not isinstance(data_flows, list):
            self.log_warning("Failed to extract data flows from LLM response")
            # Create minimal default data flows based on components
            data_flows = []
            for component in components:
                for dep in component.get("depends_on", []):
                    data_flows.append({
                        "source": component["name"],
                        "destination": dep,
                        "data_type": "Data",
                        "description": f"Data flow from {component['name']} to {dep}"
                    })

        # Create prompt for data flow diagram
        diagram_prompt = f"""
        Create a Mermaid flowchart diagram that visualizes the key data flows in the system.
        Show how data moves between components and include data types where relevant.

        Components:
        {json.dumps(components, indent=2)}

        Data Flows:
        {json.dumps(data_flows, indent=2)}

        Generate only the Mermaid diagram code in the format:
        ```mermaid
        graph LR
            A[Component A] -->|data type| B[Component B]
            ...
        ```

        Use appropriate shapes, styles, and colors to represent different components and data types.
        Keep the diagram clean and readable.
        """

        # Get diagram from LLM
        diagram_response = self.model.invoke([{"role": "system", "content": diagram_prompt}])

        # Extract Mermaid diagram code
        mermaid_code = self.parser.extract_mermaid_diagram(diagram_response.content)

        if not mermaid_code:
            self.log_warning("Failed to extract data flow diagram code")
            return None

        # Get description for the diagram
        description_prompt = f"""
        Provide a brief (2-3 paragraphs) description of the data flows shown in this diagram.
        Explain what data is being transferred between components and any important transformations or validations.

        Data Flows:
        {json.dumps(data_flows, indent=2)}

        Mermaid Diagram:
        {mermaid_code}
        """

        description_response = self.model.invoke([{"role": "system", "content": description_prompt}])

        return {
            "title": "Data Flow Diagram",
            "type": "flowchart",
            "content": mermaid_code,
            "description": description_response.content
        }

    def _generate_class_diagram(self, components: List[Dict[str, Any]],
                                report_content: str) -> Dict[str, Any]:
        """Generate a class/module dependency diagram.

        Args:
            components: Identified components
            report_content: Repository report content

        Returns:
            Diagram dictionary or None if generation failed
        """
        self.log_info("Generating class/module dependency diagram")

        # Create prompt for class/module diagram
        prompt = f"""
        Create a Mermaid class diagram showing the key classes/modules in the system and their relationships.
        Focus on the most important classes/modules and include inheritance, composition, and dependencies.

        Components:
        {json.dumps(components, indent=2)}

        Repository Report:
        {report_content[:7500]}

        Generate only the Mermaid diagram code in the format:
        ```mermaid
        classDiagram
            Class01 <|-- Class02
            Class01 *-- Class03
            Class01 o-- Class04
            Class01 --> Class05
            ...
        ```

        Include key attributes and methods for important classes.
        Use appropriate relationship types (inheritance, composition, aggregation, association).
        Keep the diagram clean and readable.
        """

        # Get diagram from LLM
        response = self.model.invoke([{"role": "system", "content": prompt}])

        # Extract Mermaid diagram code
        mermaid_code = self.parser.extract_mermaid_diagram(response.content)

        if not mermaid_code:
            self.log_warning("Failed to extract class diagram code")
            return None

        # Get description for the diagram
        description_prompt = f"""
        Provide a brief (2-3 paragraphs) description of the class/module relationships shown in this diagram.
        Explain the key classes/modules and how they relate to each other (inheritance, composition, etc.).

        Mermaid Diagram:
        {mermaid_code}
        """

        description_response = self.model.invoke([{"role": "system", "content": description_prompt}])

        return {
            "title": "Class/Module Dependency Diagram",
            "type": "class",
            "content": mermaid_code,
            "description": description_response.content
        }

    def _generate_sequence_diagrams(self, components: List[Dict[str, Any]],
                                    report_content: str) -> List[Dict[str, Any]]:
        """Generate sequence diagrams for key processes.

        Args:
            components: Identified components
            report_content: Repository report content

        Returns:
            List of sequence diagram dictionaries
        """
        self.log_info("Generating sequence diagrams for key processes")

        # Identify key processes
        processes_prompt = f"""
        Based on the repository report and components, identify 2-3 key processes or workflows in the system
        that would benefit from sequence diagram visualization. For each process, provide:
        1. Process name
        2. Description of what happens
        3. Components/actors involved in sequence
        4. Sequence of interactions between components

        Repository Report:
        {report_content[:7500]}

        Components:
        {json.dumps(components, indent=2)}

        Format your response as a JSON array of process objects, like this:
        [
          {{
            "name": "User Authentication",
            "description": "Process of authenticating a user in the system",
            "actors": ["User", "AuthController", "AuthService", "UserRepository", "TokenService"],
            "sequence": [
              "User submits credentials",
              "AuthController validates request format",
              "AuthService verifies credentials against UserRepository",
              "TokenService generates authentication token",
              "AuthService returns token to User"
            ]
          }}
        ]

        Provide only the JSON array, no other text.
        """

        # Get processes from LLM
        processes_response = self.model.invoke([{"role": "system", "content": processes_prompt}])

        # Extract JSON processes
        processes = self.parser.extract_json(processes_response.content)

        if not processes or not isinstance(processes, list):
            self.log_warning("Failed to extract processes from LLM response")
            return []

        sequence_diagrams = []

        # Generate a sequence diagram for each process
        for process in processes:
            process_name = process.get("name", "Unknown Process")
            process_description = process.get("description", "")
            actors = process.get("actors", [])
            sequence = process.get("sequence", [])

            # Skip if too little information
            if len(actors) < 2 or len(sequence) < 3:
                continue

            # Create prompt for sequence diagram
            diagram_prompt = f"""
            Create a Mermaid sequence diagram for the '{process_name}' process.
            Include all interactions between components in the correct sequence.

            Process Details:
            {json.dumps(process, indent=2)}

            Generate only the Mermaid diagram code in the format:
            ```mermaid
            sequenceDiagram
                participant A as Component A
                participant B as Component B
                A->>B: Action
                ...
            ```

            Use appropriate actors/participants and message types.
            Include activations and notes where helpful.
            Keep the diagram clean and readable.
            """

            # Get diagram from LLM
            diagram_response = self.model.invoke([{"role": "system", "content": diagram_prompt}])

            # Extract Mermaid diagram code
            mermaid_code = self.parser.extract_mermaid_diagram(diagram_response.content)

            if not mermaid_code:
                self.log_warning(f"Failed to extract sequence diagram code for {process_name}")
                continue

            sequence_diagrams.append({
                "title": f"Sequence Diagram: {process_name}",
                "type": "sequence",
                "content": mermaid_code,
                "description": process_description
            })

        self.log_info(f"Generated {len(sequence_diagrams)} sequence diagrams")
        return sequence_diagrams

    def _format_diagrams_report(self, diagrams: List[Dict[str, Any]]) -> str:
        """Format diagrams into a comprehensive report.

        Args:
            diagrams: List of diagram dictionaries

        Returns:
            Formatted diagrams report content
        """
        if not diagrams:
            return "# Architecture Diagrams\n\nNo diagrams were generated."

        report = "# Architectural and Data Flow Diagrams\n\n"

        # Executive Summary
        report += "## Executive Summary\n\n"
        summary_prompt = """
        Create a brief executive summary (2-3 paragraphs) of the architectural diagrams generated, including:
        1. Key architectural patterns identified
        2. Main components and their interactions
        3. Important data flows
        4. Key insights from the diagrams

        Keep it concise and non-technical.
        """
        summary_response = self.model.invoke([{"role": "system", "content": summary_prompt}])
        report += f"{summary_response.content}\n\n"

        # Add each diagram with its description
        for diagram in diagrams:
            report += f"## {diagram['title']}\n\n"

            if "description" in diagram:
                report += f"{diagram['description']}\n\n"

            report += f"```mermaid\n{diagram['content']}\n```\n\n"

        # Architectural Insights and Recommendations
        insights_prompt = """
        Based on the architectural and data flow diagrams, provide insights and recommendations for the architecture. Include:
        1. Architectural strengths identified
        2. Potential architectural issues or concerns
        3. Recommendations for architectural improvements
        4. Scalability, maintainability, and security considerations

        Be specific and actionable in your recommendations.
        """
        insights_response = self.model.invoke([{"role": "system", "content": insights_prompt}])
        report += "## Architectural Insights and Recommendations\n\n"
        report += f"{insights_response.content}\n\n"

        return report