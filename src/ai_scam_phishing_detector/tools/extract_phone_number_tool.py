from crewai.tools import BaseTool
from crewai_tools import SerperDevTool
from typing import Type
from pydantic import BaseModel, Field
import re


class PhoneAnalysisInput(BaseModel):
    """Input schema for PhoneAnalysisTool."""
    sender_info: str = Field(..., description="Sender information containing phone number")


class PhoneAnalysisTool(BaseTool):
    name: str = "Phone Number Analyzer"
    description: str = "Extract and analyze phone numbers to check company registration and scam flags"
    args_schema: Type[PhoneAnalysisInput] = PhoneAnalysisInput

    def _run(self, sender_info: str) -> str:
        """Extract phone number and perform comprehensive analysis."""
        
        # Extract phone number
        phone_number = self._extract_phone_number(sender_info)
        if not phone_number:
            return "❌ No phone number found"
        
        # Check company registration
        company_result = self._check_company_registration(phone_number)
        
        # Check if number is flagged as scam
        reputation_result = self._check_phone_reputation(phone_number)
        
        # Analyze area code
        area_analysis = self._analyse_area_code(phone_number)
        
        # Overall risk assessment
        risk_level = self._assess_risk(company_result, reputation_result)
        
        return f"""📞 PHONE ANALYSIS: {phone_number}

{area_analysis}

🏢 COMPANY REGISTRATION:
{company_result}

🚨 SCAM REPORTS:
{reputation_result}

⚖️ OVERALL RISK: {risk_level}"""

    def _extract_phone_number(self, text: str) -> str:
        """Extract phone number from text."""
        # Phone number patterns
        patterns = [
            r'\+\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}',  # +44 7729 864321
            r'\d{11}',  # 07729864321
            r'\d{3}[\s\-]\d{3}[\s\-]\d{4}',  # 077 298 64321
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group().replace(' ', '').replace('-', '')
        
        return ""

    def _analyse_area_code(self, phone_number: str) -> str:
        """Simple area code analysis."""
        if phone_number.startswith('+44'):
            return "🇬🇧 UK Number"
        elif phone_number.startswith('+1'):
            return "🇺🇸 US/Canada Number"
        elif phone_number.startswith('07'):
            return "🇬🇧 UK Mobile Number"
        elif phone_number.startswith('01') or phone_number.startswith('02'):
            return "🇬🇧 UK Landline"
        else:
            return "🌍 International Number"

    def _check_company_registration(self, phone_number: str) -> str:
        """Check if phone number is registered to a company or trusted organization."""
        try:
            search_tool = SerperDevTool()
            
            # Search for company registration
            search_queries = [
                f'"{phone_number}" company registered business',
                f'"{phone_number}" official contact number',
                f'"{phone_number}" legitimate business',
                f'"{phone_number}" company directory',
                f'"{phone_number}" business registration'
            ]
            
            company_indicators = 0
            company_names = []
            
            for query in search_queries:
                try:
                    result = search_tool._run(query)
                    if result:
                        result_text = str(result).lower()
                        
                        # Look for company/business indicators
                        if any(word in result_text for word in ['company', 'business', 'ltd', 'limited', 'corp', 'inc', 'plc']):
                            company_indicators += 1
                        
                        # Look for trusted organizations
                        trusted_orgs = ['bank', 'hospital', 'school', 'university', 'government', 'council', 'nhs', 'police', 'hmrc']
                        if any(org in result_text for org in trusted_orgs):
                            company_indicators += 2
                            company_names.append("Trusted Organization")
                        
                        # Extract potential company names
                        if 'company' in result_text and company_indicators > 0:
                            company_names.append("Registered Business")
                            
                except Exception:
                    continue
            
            if company_indicators >= 3:
                return f"✅ LEGITIMATE: Registered to trusted organization/company"
            elif company_indicators >= 1:
                return f"⚠️ POSSIBLE: Some business registration found"
            else:
                return f"❌ NOT FOUND: No company registration found"
                
        except Exception as e:
            return f"❓ Could not verify company registration"

    def _check_phone_reputation(self, phone_number: str) -> str:
        """Check if phone number is flagged online."""
        try:
            search_tool = SerperDevTool()
            
            # Search for scam reports
            search_queries = [
                f'"{phone_number}" scam site:who-called-me.co.uk',
                f'"{phone_number}" spam site:shouldianswer.com',
                f'"{phone_number}" fraud reported',
                f'"{phone_number}" nuisance call',
                f'"{phone_number}" scammer',
                f'"{phone_number}" who called me?',
            ]
            
            scam_flags = 0
            for query in search_queries:
                try:
                    result = search_tool._run(query)
                    if result and any(word in str(result).lower() for word in ['scam', 'spam', 'fraud', 'nuisance', 'suspicious']):
                        scam_flags += 1
                except:
                    continue
            
            if scam_flags >= 3:
                return "🚨 HIGH RISK: Multiple scam reports found"
            elif scam_flags >= 2:
                return "⚠️ MEDIUM RISK: Some scam reports found"
            elif scam_flags == 1:
                return "🔍 LOW RISK: Minimal reports found"
            else:
                return "✅ CLEAN: No scam reports found"
                
        except Exception as e:
            return f"❓ Could not check reputation"

    def _assess_risk(self, company_result: str, reputation_result: str) -> str:
        """Assess overall risk based on company registration and reputation."""
        
        # High risk if scam reports found
        if "HIGH RISK" in reputation_result:
            return "🚨 HIGH RISK - Known scammer number"
        
        # Low risk if legitimate company and no scam reports
        if "LEGITIMATE" in company_result and "CLEAN" in reputation_result:
            return "✅ LOW RISK - Legitimate business number"
        
        # Medium risk if some business registration but some concerns
        if "POSSIBLE" in company_result and "MEDIUM RISK" in reputation_result:
            return "⚠️ MEDIUM RISK - Mixed indicators"
        
        # High risk if no company registration and any scam reports
        if "NOT FOUND" in company_result and ("MEDIUM RISK" in reputation_result or "LOW RISK" in reputation_result):
            return "🚨 HIGH RISK - Unregistered number with complaints"
        
        # Default medium risk for unverified numbers
        return "⚠️ MEDIUM RISK - Cannot verify legitimacy"