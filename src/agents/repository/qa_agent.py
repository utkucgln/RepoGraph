"""
Repository question and answer agent.

This module provides an agent that answers questions about a repository
and generates code based on user queries.
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

from src.core.agent_base import Agent
from src.utils.file_utils import read_file


class RepositoryQAAgent(Agent):
    """Agent for answering questions about a repository.

    This agent can answer specific questions about a repository's
    structure, functionality, and can generate code examples.
    """

    def __init__(self, name: str, model: Any, tools: Optional[List] = None):
        """Initialize the repository Q&A agent.

        Args:
            name: Name of the agent
            model: LLM model to use
            tools: List of tools the agent can use
        """
        super().__init__(name, model, tools)

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Process the current state and answer repository questions.

        Args:
            state: Current state containing repository information and user query

        Returns:
            Updated state with answer to user's question
        """
        self.log_info("Repository Q&A Agent: Starting question answering")

        # Extract user query and repository path
        user_query, repo_path = self._extract_query_and_path(state)

        if not user_query:
            self.log_error("Repository Q&A Agent: No user query found")
            error_msg = "No user query found. Please provide a question about the repository."
            return self.add_message_to_state(state, error_msg, "system", "error")

        if not repo_path:
            self.log_error("Repository Q&A Agent: No repository path found")
            error_msg = "No repository path found. Repository loader must run first."
            return self.add_message_to_state(state, error_msg, "system", "error")

        # Get repository context information
        context = self._gather_context(state)

        # Determine the type of question
        question_type = self._determine_question_type(user_query)

        # Process the question and generate an answer
        answer = self._answer_question(user_query, question_type, context, repo_path, state)

        # Add answer to state
        state = self.add_message_to_state(state, answer, "system", "qa_response")

        self.log_info("Repository Q&A Agent: Question answering complete")
        return state

    def _extract_query_and_path(self, state: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract user query and repository path from state.

        Args:
            state: Current state

        Returns:
            Tuple of (user_query, repo_path)
        """
        user_query = None
        repo_path = None

        # Extract user query from the last human message
        for message in reversed(state.get("messages", [])):
            if isinstance(message, dict) and message.get("role") == "user":
                user_query = message.get("content", "")
                break
            elif hasattr(message, "type") and message.type == "human":
                user_query = getattr(message, "content", "")
                break

        # Extract repository path
        repo_path = state.get("repo_path")
        if not repo_path:
            # Try to extract from messages
            for message in state.get("messages", []):
                if isinstance(message, dict):
                    content = message.get("content", "")
                else:
                    content = getattr(message, "content", "")

                if "Path:" in content:
                    parts = content.split("Path:")
                    if len(parts) > 1:
                        repo_path = parts[1].strip()
                        if "\n" in repo_path:
                            repo_path = repo_path.split("\n")[0].strip()
                        break

        # Clean up user query by removing the repository path part
        if repo_path and user_query and "Path:" in user_query:
            user_query = re.sub(r'Path:\s*[^\n]+', '', user_query).strip()

        return user_query, repo_path

    def _gather_context(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Gather repository context for answering questions.

        Args:
            state: Current state

        Returns:
            Dictionary with context information
        """
        context = {}

        # Get file list
        file_list_message = self.get_last_message_by_name(state, "file_list")
        if file_list_message:
            content = file_list_message.get("content", "")
            if "Files:" in content:
                file_list = content.split("Files:")[1].strip().split("\n")
                context["file_list"] = file_list

        # Get file descriptions
        file_descriptions_message = self.get_last_message_by_name(state, "file_descriptions")
        if file_descriptions_message:
            content = file_descriptions_message.get("content", "")
            context["file_descriptions"] = content

        # Get repository report
        report_message = self.get_last_message_by_name(state, "report")
        if report_message:
            content = report_message.get("content", "")
            context["report"] = content

        # Get architecture diagrams
        diagrams_message = self.get_last_message_by_name(state, "architecture_diagrams")
        if diagrams_message:
            content = diagrams_message.get("content", "")
            context["diagrams"] = content

        return context

    def _determine_question_type(self, query: str) -> str:
        """Determine the type of question being asked.

        Args:
            query: User query

        Returns:
            Question type (code_structure, code_generation, etc.)
        """
        # Define patterns for different question types
        patterns = {
            "code_structure": [
                r"structure", r"organization", r"layout", r"architecture",
                r"how (is|are) .* structured", r"what does .* look like"
            ],
            "code_generation": [
                r"(generate|create|write|implement) (a|some|an)? code",
                r"how (would|do) I (code|implement|write)",
                r"can you (code|make|develop)"
            ],
            "explanation": [
                r"explain", r"what (is|are|does)", r"how does",
                r"why (is|are|does)", r"describe"
            ],
            "usage": [
                r"how (to|do I) use", r"usage", r"example",
                r"how (can|could|would|should) I"
            ],
            "architecture": [
                r"architecture", r"design pattern", r"components?",
                r"modules?", r"services?"
            ],
            "dependencies": [
                r"dependencies", r"imports", r"requires", r"depends on"
            ],
            "patterns": [
                r"patterns?", r"practices", r"idioms", r"techniques", r"approaches"
            ],
            "best_practices": [
                r"best practices", r"standards", r"conventions",
                r"guidelines", r"recommendations"
            ]
        }

        # Check each pattern against the query
        for question_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, query, re.IGNORECASE):
                    self.log_info(f"Detected question type: {question_type}")
                    return question_type

        # Default to "other" if no pattern matches
        self.log_info("No specific question type detected, using 'other'")
        return "other"

    def _answer_question(self, query: str, question_type: str,
                         context: Dict[str, Any], repo_path: str,
                         state: Dict[str, Any]) -> str:
        """Answer the user's question based on type and context.

        Args:
            query: User query
            question_type: Type of question
            context: Context information
            repo_path: Repository path
            state: Current state

        Returns:
            Answer to the question
        """
        # Define contexts for answering different types of questions
        contexts = {
            "code_structure": "I'll analyze the repository structure to answer this question.",
            "code_generation": "I'll generate code based on the repository context.",
            "explanation": "I'll explain concepts based on the repository implementation.",
            "usage": "I'll provide examples of how to use components from this repository.",
            "architecture": "I'll analyze the architecture to answer this question.",
            "dependencies": "I'll examine the dependencies to answer this question.",
            "patterns": "I'll identify patterns used in the repository to answer this question.",
            "best_practices": "I'll review the codebase for best practices to answer this question."
        }

        # For code generation, find relevant files
        if question_type == "code_generation":
            relevant_files = self._find_relevant_files(query, context.get("file_list", []), repo_path)
            file_contents = {}

            for file_path in relevant_files:
                try:
                    full_path = os.path.join(repo_path, file_path)
                    content = read_file(full_path)
                    if content:
                        file_contents[file_path] = content
                except Exception as e:
                    self.log_error(f"Error reading {file_path}: {str(e)}")

            # Add file contents to context
            file_contents_text = ""
            for file_path, content in file_contents.items():
                file_contents_text += f"--- {file_path} ---\n{content[:5000]}\n\n"

            context["relevant_files"] = file_contents_text

        # Create the response prompt
        context_text = ""

        # Add file list counts
        if "file_list" in context:
            context_text += f"Repository contains {len(context['file_list'])} files.\n\n"

        # Add condensed descriptions
        if "file_descriptions" in context:
            # Extract a condensed version of file descriptions
            description_lines = context["file_descriptions"].split("\n")
            condensed_descriptions = "\n".join(description_lines[:50])
            if len(description_lines) > 50:
                condensed_descriptions += "\n... (truncated)"
            context_text += condensed_descriptions + "\n\n"

        # Add architecture information for architecture-related questions
        if question_type in ["architecture", "code_structure", "patterns"] and "report" in context:
            # Extract architecture section from report
            architecture_match = re.search(
                r'## (?:\d\.)?\s*Architecture\s+Overview.*?(?=##\s+\d\.)',
                context["report"],
                re.DOTALL | re.IGNORECASE
            )
            if architecture_match:
                architecture_section = architecture_match.group(0)[:2000] + "\n... (truncated)"
                context_text += architecture_section + "\n\n"

        # Add relevant file contents for code generation
        if question_type == "code_generation" and "relevant_files" in context:
            context_text += context["relevant_files"]

        # Generate the response
        prompt = f"""
        You are a repository expert and code generation assistant, helping a user understand and work with a code repository.
        The user has asked: "{query}"

        Based on this question, I've identified it as a '{question_type}' question. {contexts.get(question_type, '')}

        Here's information about the repository to help you answer:

        {context_text}

        Please provide a helpful and specific response that directly addresses the user's question.
        If the question is about code generation, include concrete code examples that could be implemented
        based on the repository's patterns and architecture.

        Format your response to be clear and organized, with code examples in appropriate code blocks.
        """

        # Get response from LLM
        self.log_info("Invoking LLM for question answering")
        response = self.model.invoke([{"role": "system", "content": prompt}])

        return response.content

    def _find_relevant_files(self, query: str, file_list: List[str], repo_path: str) -> List[str]:
        """Find files that might be relevant to the query.

        Args:
            query: User query
            file_list: List of files in the repository
            repo_path: Repository path

        Returns:
            List of relevant file paths
        """
        # Extract key terms from the query
        terms = set(re.findall(r'\b[a-zA-Z][a-zA-Z0-9_]+\b', query.lower()))

        # Remove common stop words
        stop_words = {"a", "an", "the", "this", "that", "these", "those", "is", "are", "was", "were",
                      "be", "been", "being", "have", "has", "had", "do", "does", "did", "will",
                      "would", "shall", "should", "may", "might", "must", "can", "could", "to",
                      "for", "of", "in", "on", "at", "by", "with", "about", "against", "between",
                      "into", "through", "during", "before", "after", "above", "below", "from",
                      "up", "down", "and", "but", "or", "as", "if", "then", "else", "when",
                      "where", "why", "how", "all", "any", "both", "each", "few", "more",
                      "most", "other", "some", "such", "no", "nor", "not", "only", "own",
                      "same", "so", "than", "too", "very", "just", "code", "file", "create",
                      "write", "implement", "generate", "example"}
        terms -= stop_words

        self.log_info(f"Key terms extracted from query: {terms}")

        # Score files based on relevance to the query
        scored_files = []

        for file_path in file_list:
            score = 0

            # Check filename
            filename = os.path.basename(file_path).lower()
            for term in terms:
                if term in filename:
                    score += 3  # Higher weight for terms in filename

            # Check file path
            file_path_lower = file_path.lower()
            for term in terms:
                if term in file_path_lower:
                    score += 1

            # Boost score for common important files
            important_patterns = [
                r'app\.(py|js|ts)$',
                r'main\.(py|js|ts)$',
                r'index\.(py|js|ts)$',
                r'config\.(py|js|json|yaml|yml)$',
                r'settings\.(py|js|json|yaml|yml)$'
            ]

            for pattern in important_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    score += 2

            if score > 0:
                scored_files.append((file_path, score))

        # Sort by score and limit to top results
        scored_files.sort(key=lambda x: x[1], reverse=True)
        top_files = [file_path for file_path, _ in scored_files[:5]]

        # If we have fewer than 3 files, add some important files
        if len(top_files) < 3:
            important_files = []
            for file_path in file_list:
                filename = os.path.basename(file_path).lower()
                if any(name in filename for name in ["app", "main", "index", "config", "settings"]):
                    important_files.append(file_path)

            # Add important files not already in top_files
            for file_path in important_files:
                if file_path not in top_files:
                    top_files.append(file_path)
                    if len(top_files) >= 5:
                        break

        self.log_info(f"Selected {len(top_files)} relevant files for the query")
        return top_files