"""Layer 7: Prompt Injection Detection.

This module detects instruction-like text in SQL comments and string literals
that could be used to manipulate LLM-based query systems or downstream processing.

Security Model:
- Pattern-based detection (not LLM-based)
- Checks SQL comments for instruction keywords
- Checks string literals for malicious content
- Detects privilege escalation attempts
- Identifies encoding/obfuscation patterns

Error Codes: E701-E799
"""

import re
from pathlib import Path
from typing import Any, cast

import sqlparse  # type: ignore[import-untyped]
import yaml
from sqlparse.tokens import String  # type: ignore[import-untyped]

from ..errors import (
    InstructionInCommentError,
    InstructionInStringError,
    ObfuscationDetectedError,
    PrivilegeEscalationError,
)
from ..models import ValidationResult


class PromptInjectionDetector:
    """Detects prompt injection patterns in SQL queries."""

    def __init__(self, config_path: Path | None = None) -> None:
        """Initialize prompt injection detector with configuration.

        Args:
            config_path: Path to prompt patterns configuration YAML file
        """
        self.config = self._load_config(config_path)
        self.instruction_keywords = set(
            k.lower() for k in self.config.get("instruction_keywords", [])
        )
        self.privilege_keywords = set(
            k.lower() for k in self.config.get("privilege_keywords", [])
        )
        self.dangerous_phrases = [
            p.lower() for p in self.config.get("dangerous_phrases", [])
        ]
        # Pre-compile regex patterns for performance
        self.encoding_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.config.get("encoding_patterns", [])
        ]
        self.min_phrase_length = self.config.get("min_phrase_length", 10)

    def _load_config(self, config_path: Path | None) -> dict:
        """Load prompt injection patterns from YAML configuration.

        Args:
            config_path: Path to configuration file

        Returns:
            Dictionary of prompt injection patterns
        """
        if config_path is None:
            # Use default configuration path
            config_path = (
                Path(__file__).parent.parent.parent / "config" / "prompt_patterns.yaml"
            )

        if not config_path.exists():
            # Return hardcoded minimal defaults if config not found
            return self._get_default_config()

        with open(config_path) as f:
            data = yaml.safe_load(f)
            return cast(dict[Any, Any], data.get("prompt_injection", {}))

    def _get_default_config(self) -> dict:
        """Get default prompt injection patterns (hardcoded fallback).

        Returns:
            Dictionary of prompt injection patterns
        """
        return {
            "instruction_keywords": ["ignore", "disable", "override", "bypass"],
            "privilege_keywords": ["admin", "root", "superuser"],
            "dangerous_phrases": [
                "ignore previous instructions",
                "disable validation",
                "bypass security",
            ],
            "encoding_patterns": [
                r"\\x[0-9a-fA-F]{2}",
                r"\\u[0-9a-fA-F]{4}",
            ],
            "min_phrase_length": 10,
        }

    def check_text(self, text: str, context: str = "comment") -> None:
        """Check text for prompt injection patterns.

        Args:
            text: Text to check (comment or string literal)
            context: "comment" or "string" for error reporting

        Raises:
            InstructionInCommentError: If instruction detected in comment
            InstructionInStringError: If instruction detected in string
            PrivilegeEscalationError: If privilege keyword found
            ObfuscationDetectedError: If encoding detected
        """
        text_lower = text.lower()

        # Check for dangerous phrases first (most specific)
        for phrase in self.dangerous_phrases:
            if len(phrase) >= self.min_phrase_length and phrase in text_lower:
                if context == "comment":
                    raise InstructionInCommentError(text, phrase)
                else:
                    raise InstructionInStringError(text, phrase)

        # Extract words from text (alphanumeric sequences)
        words = re.findall(r"\b\w+\b", text_lower)

        # Check for instruction keywords
        for word in words:
            if word in self.instruction_keywords:
                if context == "comment":
                    raise InstructionInCommentError(text, word)
                else:
                    raise InstructionInStringError(text, word)

            # Check privilege keywords (always raise E703 regardless of context)
            if word in self.privilege_keywords:
                raise PrivilegeEscalationError(text, word)

        # Check for encoding/obfuscation patterns
        for pattern in self.encoding_patterns:
            match = pattern.search(text)
            if match:
                raise ObfuscationDetectedError(text, pattern.pattern)


def validate_prompt_injection(query: str) -> None:
    """Validate query for prompt injection attempts.

    Args:
        query: SQL query to validate

    Raises:
        InstructionInCommentError: If instruction detected in comment
        InstructionInStringError: If instruction detected in string
        PrivilegeEscalationError: If privilege escalation detected
        ObfuscationDetectedError: If encoding/obfuscation detected

    Note:
        This function follows the same pattern as other validators - it raises
        an exception if validation fails, and returns None if validation passes.
        The main validator pipeline will catch exceptions and convert them to
        ValidationResult objects.
    """
    detector = PromptInjectionDetector()

    # Parse query using sqlparse
    parsed = sqlparse.parse(query)
    if not parsed:
        # Empty query - let ASCII validator handle this
        return

    statement = parsed[0]

    # Extract and check all comments
    comments = _extract_comments(statement)
    for comment in comments:
        detector.check_text(comment, context="comment")

    # Extract and check all string literals
    strings = _extract_strings(statement)
    for string in strings:
        detector.check_text(string, context="string")


def _extract_comments(statement: Any) -> list[str]:
    """Extract all comments from SQL statement.

    Args:
        statement: Parsed SQL statement

    Returns:
        List of comment text (without comment markers)
    """
    from sqlparse.tokens import Comment as CommentToken

    comments: list[str] = []

    def _recurse(token: Any) -> None:
        # Check if token type is a comment
        if hasattr(token, "ttype") and token.ttype in CommentToken:
            # Remove comment markers (-- or /* */)
            text = str(token).strip()
            # Remove -- prefix
            if text.startswith("--"):
                text = text[2:].strip()
            # Remove /* */ markers
            if text.startswith("/*") and text.endswith("*/"):
                text = text[2:-2].strip()
            if text:
                comments.append(text)
        # Also recurse into compound tokens
        if hasattr(token, "tokens"):
            for subtoken in token.tokens:
                _recurse(subtoken)

    _recurse(statement)
    return comments


def _extract_strings(statement: Any) -> list[str]:
    """Extract all string literals from SQL statement.

    Args:
        statement: Parsed SQL statement

    Returns:
        List of string literal values (without quotes)
    """
    strings: list[str] = []

    def _recurse(token: Any) -> None:
        # Check for string token types
        if hasattr(token, "ttype") and token.ttype is not None:
            if token.ttype in String.Single or token.ttype in String.Symbol:
                # Remove quotes
                text = str(token).strip().strip("'").strip('"')
                if text:
                    strings.append(text)
        elif hasattr(token, "tokens"):
            for subtoken in token.tokens:
                _recurse(subtoken)

    _recurse(statement)
    return strings
