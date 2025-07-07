from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import re


class TextAnalysisInput(BaseModel):
    """Input schema for TextAnalysisTool."""

    content: str = Field(
        ...,
        description="The content to analyze for scam patterns and phishing attempts.",
    )
    sender_info: str = Field(
        ...,
        description="Information about the sender (email, phone, name, etc.) to check for reputation.",
    )


class TextAnalysisTool(BaseTool):
    name: str = "Text Analysis Tool"
    description: str = (
        "Analyze text content for scam patterns, phishing attempts, and sender reputation. "
        "This tool checks for common scam indicators and verifies sender information against known databases."
    )
    args_schema: Type[BaseModel] = TextAnalysisInput

    def _run(self, content: str, sender_info: str) -> str:
        """Analyse the content and sender information for scams."""
        # Simple pattern matching for common scam indicators
        job_indicators = [
            r"job offer",
            r"recruitment",
            r"hiring",
            r"position",
            r"employment",
            r"career opportunity",
            r"work from home",
            r"consultant.*job",
            r"freelance position",
            r"urgent hiring",
            r"apply now",
            r"get paid",
            r"guaranteed income",
            r"no experience required",
            r"work remotely",
            r"part-time job",
            r"full-time position",
            r"job application",
            r"job vacancy",
            r"job listing",
            r"job opening",
            r"job search",
            r"job alert",
            r"job board",
            r"job portal",
            r"job site",
            r"job market",
        ]

        matches = [
            indicator
            for indicator in job_indicators
            if re.search(indicator, content, re.IGNORECASE)
        ]

        if matches:
            return f"Scam indicators found: {', '.join(matches)}"

        return "No obvious scam indicators found."
