from crewai.tools import BaseTool
from crewai_tools import SerperDevTool
from typing import Type
from pydantic import BaseModel, Field


class ReputationSearchInput(BaseModel):
    """Input schema for ReputationSearchTool."""
    sender_info: str = Field(..., description="The sender information to search for (email, phone, name, etc.)")


class ReputationSearchTool(BaseTool):
    name: str = "Reputation Search Tool"
    description: str = (
        "Search the web to check if sender information has been flagged as a scam. "
        "This tool searches scam databases, forums, and complaint sites to verify reputation."
    )
    args_schema: Type[BaseModel] = ReputationSearchInput

    def _run(self, sender_info: str) -> str:
        """Search for reputation information about the sender."""
        try:
            search_tool = SerperDevTool()
            
            # Create search queries to check for scam reports
            search_queries = [
                f'"{sender_info}" scam',
                f'"{sender_info}" fraud',
                f'"{sender_info}" phishing',
                f'"{sender_info}" complaint',
                f'"{sender_info}" reported'
            ]
            
            all_results = []
            scam_indicators = 0
            
            # Perform searches
            for query in search_queries:
                try:
                    result = search_tool._run(query)
                    if result:
                        all_results.append(f"Query: {query}")
                        all_results.append(f"Results: {result}")
                        
                        # Count scam indicators
                        result_text = str(result).lower()
                        if any(word in result_text for word in ['scam', 'fraud', 'phishing', 'complaint', 'reported', 'suspicious']):
                            scam_indicators += 1
                        
                        all_results.append("---")
                        
                except Exception as e:
                    all_results.append(f"Error searching '{query}': {str(e)}")
                    continue
            
            # Generate summary
            if scam_indicators >= 3:
                risk_level = "HIGH - Strong evidence of scam reports"
            elif scam_indicators >= 2:
                risk_level = "MEDIUM - Some scam indicators found"
            elif scam_indicators >= 1:
                risk_level = "LOW - Few scam indicators found"
            else:
                risk_level = "CLEAN - No scam indicators found"
            
            summary = f"""
=== REPUTATION SEARCH RESULTS ===
Sender: {sender_info}
Risk Level: {risk_level}
Scam Indicators Found: {scam_indicators}/5 searches

=== DETAILED RESULTS ===
{chr(10).join(all_results)}
            """
            
            return summary
            
        except Exception as e:
            return f"Error performing reputation search: {str(e)}"
