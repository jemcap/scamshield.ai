from crewai.tools import BaseTool
from crewai_tools import SerperDevTool
from typing import Type, List, Dict, Any
from pydantic import BaseModel, Field
import re
import requests
from urllib.parse import urlparse, unquote
import socket
import ssl
import whois
from datetime import datetime, timedelta


class LinkAnalysisInput(BaseModel):
    """Input schema for LinkAnalysisTool."""

    content: str = Field(
        ..., description="The message content to extract and analyze links from"
    )


class LinkAnalysisOutput(BaseModel):
    """Output schema for LinkAnalysisTool."""

    extracted_urls: List[str] = Field(
        ..., description="List of URLs found in the content"
    )
    analysis_results: List[Dict[str, Any]] = Field(
        ..., description="Detailed analysis for each URL"
    )
    overall_risk: str = Field(
        ..., description="Overall risk assessment: LOW, MEDIUM, HIGH, CRITICAL"
    )
    malicious_urls: List[str] = Field(..., description="URLs identified as malicious")
    summary: str = Field(..., description="Human-readable summary of the analysis")


class LinkAnalysisTool(BaseTool):
    name: str = "Link Analysis Tool"
    description: str = (
        """A comprehensive tool to extract URLs from content and perform deep security analysis.
        It checks for malicious links, phishing sites, URL shorteners, suspicious domains,
        and searches the web for reputation information about each URL."""
    )
    args_schema: Type[LinkAnalysisInput] = LinkAnalysisInput

    def _extract_urls(self, content: str) -> List[str]:
        """Extract all URLs from the given content."""
        # Comprehensive URL regex patterns
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',  # Standard HTTP/HTTPS URLs
            r'www\.[^\s<>"{}|\\^`\[\]]+',  # www URLs without protocol
            r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}[/\w\-._~:/?#[\]@!$&\'()*+,;=]*",  # Domain with path
        ]

        urls = set()

        for pattern in url_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                url = match.group().strip()
                # Clean up common trailing punctuation
                url = re.sub(r"[.,;!?]+$", "", url)

                # Add protocol if missing
                if not url.startswith(("http://", "https://")):
                    if url.startswith("www."):
                        url = "https://" + url
                    elif "." in url and not url.startswith(("ftp://", "mailto:")):
                        url = "https://" + url

                # Basic validation
                if "." in url and len(url) > 4:
                    urls.add(url)

        return list(urls)

    def _check_url_shorteners(self, url: str) -> Dict[str, Any]:
        """Check if URL uses a URL shortener service."""
        shortener_services = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "short.link",
            "ow.ly",
            "buff.ly",
            "tiny.cc",
            "is.gd",
            "v.gd",
            "rb.gy",
            "cutt.ly",
            "short.io",
            "rebrand.ly",
            "bl.ink",
        ]

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        is_shortener = any(service in domain for service in shortener_services)

        result = {"is_shortener": is_shortener, "service": None, "final_url": url}

        if is_shortener:
            for service in shortener_services:
                if service in domain:
                    result["service"] = service
                    break

            # Try to expand the URL
            try:
                response = requests.head(url, allow_redirects=True, timeout=10)
                result["final_url"] = response.url
            except:
                pass

        return result
    
    def _analyse_web_content(self, url: str) -> Dict[str, Any]:
        """Fetch and analyse actual web content for security indicators."""
        try:
            response = requests.get(url, timeout=10)
            content = response.text
            headers = response.headers

            analysis = {
                "url": url,
                "content_length": len(content),
                "content_type": headers.get("Content-Type", ""),
                "has_login_form": False,
                "has_sensitive_keywords": False,
                "suspicious_headers": [],
            }

            # Check for login forms
            if re.search(r'<form[^>]*action=["\']?[^"\'>]*login[^"\'>]*["\']?[^>]*>', content, re.IGNORECASE):
                analysis["has_login_form"] = True

            # Check for sensitive keywords
            sensitive_keywords = ["password", "username", "login", "account", "secure"]
            for keyword in sensitive_keywords:
                if keyword in content.lower():
                    analysis["has_sensitive_keywords"] = True
                    break

            # Check for suspicious headers
            suspicious_headers = ["X-Powered-By", "Server", "X-Frame-Options"]
            for header in suspicious_headers:
                if header in headers:
                    analysis["suspicious_headers"].append(header)

            return analysis

        except requests.RequestException as e:
            return {"url": url, "error": str(e)}

    def _analyse_domain_safety(self, url: str) -> Dict[str, Any]:
        """analyse domain for safety indicators."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        safety_analysis = {
            "domain": domain,
            "suspicious_indicators": [],
            "risk_score": 0,
            "domain_age": None,
            "ssl_valid": False,
            "ip_address": None,
        }

        # Check for suspicious domain patterns
        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):  # IP address
            safety_analysis["suspicious_indicators"].append(
                "Uses IP address instead of domain"
            )
            safety_analysis["risk_score"] += 30

        if len(domain.split(".")) > 4:  # Too many subdomains
            safety_analysis["suspicious_indicators"].append("Excessive subdomains")
            safety_analysis["risk_score"] += 20

        if re.search(r"[0-9]{4,}", domain):  # Long numbers in domain
            safety_analysis["suspicious_indicators"].append(
                "Contains long numeric sequences"
            )
            safety_analysis["risk_score"] += 15

        # Check for suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".click", ".download", ".top"]
        if any(tld in domain for tld in suspicious_tlds):
            safety_analysis["suspicious_indicators"].append(
                "Uses suspicious top-level domain"
            )
            safety_analysis["risk_score"] += 25

        # Check for typosquatting of popular domains
        popular_domains = [
            "amazon",
            "paypal",
            "google",
            "microsoft",
            "apple",
            "facebook",
            "bank",
        ]
        for pop_domain in popular_domains:
            if pop_domain in domain and not domain.startswith(f"{pop_domain}."):
                safety_analysis["suspicious_indicators"].append(
                    f"Possible typosquatting of {pop_domain}"
                )
                safety_analysis["risk_score"] += 35

        # Try to get domain registration info
        try:
            if whois is not None:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date

                    if creation_date:
                        domain_age = (datetime.now() - creation_date).days
                        safety_analysis["domain_age"] = domain_age

                        if domain_age < 30:  # Very new domain
                            safety_analysis["suspicious_indicators"].append(
                                "Domain registered very recently"
                            )
                            safety_analysis["risk_score"] += 40
                        elif domain_age < 90:  # New domain
                            safety_analysis["suspicious_indicators"].append(
                                "Domain registered recently"
                            )
                            safety_analysis["risk_score"] += 20
        except:
            pass

        # Check SSL certificate
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    safety_analysis["ssl_valid"] = True
        except:
            safety_analysis["suspicious_indicators"].append("No valid SSL certificate")
            safety_analysis["risk_score"] += 30

        # Get IP address
        try:
            safety_analysis["ip_address"] = socket.gethostbyname(domain)
        except:
            pass

        return safety_analysis

    def _check_malicious_patterns(self, url: str) -> Dict[str, Any]:
        """Check for malicious URL patterns."""
        malicious_patterns = {
            "phishing_keywords": [
                "login",
                "signin",
                "account",
                "verify",
                "secure",
                "update",
                "confirm",
                "suspended",
                "limited",
                "urgent",
                "immediate",
                "auth",
                "expire",
                "click",
            ],
            "suspicious_paths": [
                "/phish/",
                "/scam/",
                "/fake/",
                "/clone/",
                "/mirror/",
                "/proxy/",
                "/redirect/",
                "/forward/",
            ],
            "suspicious_params": [
                "redirect",
                "url",
                "link",
                "goto",
                "target",
                "continue",
                "return",
                "next",
                "forward",
            ],
        }

        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()

        patterns_found = []
        risk_score = 0

        # Check for phishing keywords in path
        for keyword in malicious_patterns["phishing_keywords"]:
            if keyword in path:
                patterns_found.append(f"Phishing keyword in path: {keyword}")
                risk_score += 15

        # Check for suspicious paths
        for sus_path in malicious_patterns["suspicious_paths"]:
            if sus_path in path:
                patterns_found.append(f"Suspicious path pattern: {sus_path}")
                risk_score += 25

        # Check for suspicious query parameters
        for param in malicious_patterns["suspicious_params"]:
            if param in query:
                patterns_found.append(f"Suspicious parameter: {param}")
                risk_score += 20

        # Check for encoded URLs (potential obfuscation)
        if "%" in url and len(re.findall(r"%[0-9a-fA-F]{2}", url)) > 3:
            patterns_found.append(
                "URL contains excessive encoding (possible obfuscation)"
            )
            risk_score += 20

        return {"patterns_found": patterns_found, "risk_score": risk_score}

    def _search_url_reputation(self, url: str) -> Dict[str, Any]:
        """Search the web for reputation information about the URL."""
        try:
            search_tool = SerperDevTool()
            parsed = urlparse(url)
            domain = parsed.netloc

            search_queries = [
                f'"{url}" malicious',
                f'"{url}" phishing',
                f'"{url}" scam',
                f'"{domain}" blacklist',
                f'"{domain}" malware',
                f'site:virustotal.com "{domain}"',
                f'site:urlvoid.com "{domain}"',
            ]

            reputation_data = {
                "malicious_reports": [],
                "reputation_sources": [],
                "total_flags": 0,
            }

            for query in search_queries[:5]:  # Limit to avoid rate limits
                try:
                    result = search_tool._run(query)
                    if result and "organic" in result:
                        for item in result["organic"]:
                            title = item.get("title", "").lower()
                            snippet = item.get("snippet", "").lower()
                            link = item.get("link", "")

                            # Check for malicious indicators
                            malicious_keywords = [
                                "malicious",
                                "phishing",
                                "scam",
                                "malware",
                                "blacklist",
                                "dangerous",
                            ]
                            if any(
                                keyword in title + snippet
                                for keyword in malicious_keywords
                            ):
                                reputation_data["total_flags"] += 1
                                reputation_data["malicious_reports"].append(
                                    {
                                        "title": item.get("title", ""),
                                        "snippet": snippet[:100] + "...",
                                        "source": link,
                                    }
                                )

                                if link not in reputation_data["reputation_sources"]:
                                    reputation_data["reputation_sources"].append(link)

                except Exception as e:
                    continue

            return reputation_data

        except Exception as e:
            return {
                "malicious_reports": [],
                "reputation_sources": [],
                "total_flags": 0,
                "error": str(e),
            }

    def _calculate_overall_risk(self, url_analysis: Dict[str, Any]) -> str:
        """Calculate overall risk level for a URL."""
        total_risk = 0

        # Add risk from domain safety
        total_risk += url_analysis.get("domain_safety", {}).get("risk_score", 0)

        # Add risk from malicious patterns
        total_risk += url_analysis.get("malicious_patterns", {}).get("risk_score", 0)

        # Add risk from reputation
        reputation_flags = url_analysis.get("reputation", {}).get("total_flags", 0)
        total_risk += reputation_flags * 20

        # Add risk from URL shorteners (moderate risk)
        if url_analysis.get("shortener", {}).get("is_shortener", False):
            total_risk += 15

        # Determine risk level
        if total_risk >= 50:
            return "CRITICAL"
        elif total_risk >= 35:
            return "HIGH"
        elif total_risk >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def _run(self, content: str) -> str:
        """Analyse all URLs found in the content."""
        try:
            # Extract URLs from content
            urls = self._extract_urls(content)

            if not urls:
                return "No URLs found in the provided content."

            analysis_results = []
            malicious_urls = []
            highest_risk = "LOW"

            for url in urls:
                print(f"Analyzing URL: {url}")

                # Perform comprehensive analysis
                url_analysis = {
                    "url": url,
                    "shortener": self._check_url_shorteners(url),
                    "web_content": self._analyse_web_content(url),
                    "domain_safety": self._analyse_domain_safety(url),
                    "malicious_patterns": self._check_malicious_patterns(url),
                    "reputation": self._search_url_reputation(url),
                }

                # Calculate risk for this URL
                url_risk = self._calculate_overall_risk(url_analysis)
                url_analysis["risk_level"] = url_risk

                # Update overall risk
                risk_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                if risk_levels.index(url_risk) > risk_levels.index(highest_risk):
                    highest_risk = url_risk

                # Mark as malicious if high risk
                if url_risk in ["HIGH", "CRITICAL"]:
                    malicious_urls.append(url)

                analysis_results.append(url_analysis)

            # Generate summary
            summary = self._generate_summary(
                urls, analysis_results, highest_risk, malicious_urls
            )

            # Format detailed results
            detailed_output = f"""
=== LINK ANALYSIS RESULTS ===

URLs Found: {len(urls)}
Overall Risk Level: {highest_risk}
Malicious URLs: {len(malicious_urls)}

=== SUMMARY ===
{summary}

=== DETAILED ANALYSIS ===
"""

            for i, analysis in enumerate(analysis_results, 1):
                detailed_output += f"""
--- URL {i}: {analysis['url']} ---
Risk Level: {analysis['risk_level']}

URL Shortener: {'Yes' if analysis['shortener']['is_shortener'] else 'No'}
{f"Service: {analysis['shortener']['service']}" if analysis['shortener']['is_shortener'] else ""}
{f"Final URL: {analysis['shortener']['final_url']}" if analysis['shortener']['is_shortener'] else ""}

Domain Safety:
- Domain: {analysis['domain_safety']['domain']}
- Risk Score: {analysis['domain_safety']['risk_score']}/100
- SSL Valid: {analysis['domain_safety']['ssl_valid']}
- Domain Age: {analysis['domain_safety']['domain_age'] or 'Unknown'} days
- Suspicious Indicators: {len(analysis['domain_safety']['suspicious_indicators'])}
"""

                for indicator in analysis["domain_safety"]["suspicious_indicators"]:
                    detailed_output += f"  • {indicator}\n"

                detailed_output += f"""
Malicious Patterns:
- Risk Score: {analysis['malicious_patterns']['risk_score']}/100
- Patterns Found: {len(analysis['malicious_patterns']['patterns_found'])}
"""

                for pattern in analysis["malicious_patterns"]["patterns_found"]:
                    detailed_output += f"  • {pattern}\n"

                detailed_output += f"""
Reputation Check:
- Total Flags: {analysis['reputation']['total_flags']}
- Malicious Reports: {len(analysis['reputation']['malicious_reports'])}
"""

                for report in analysis["reputation"]["malicious_reports"][
                    :3
                ]:  # Show top 3
                    detailed_output += f"  • {report['title'][:60]}...\n"

                detailed_output += "\n" + "=" * 60 + "\n"

            return detailed_output

        except Exception as e:
            return f"Error during link analysis: {str(e)}"

    def _generate_summary(
        self,
        urls: List[str],
        analyses: List[Dict],
        overall_risk: str,
        malicious_urls: List[str],
    ) -> str:
        """Generate a human-readable summary."""
        if not malicious_urls:
            return f"Analysed {len(urls)} URL(s). No malicious links detected. Overall risk: {overall_risk}."

        summary = f"WARNING: Found {len(malicious_urls)} potentially malicious URL(s) out of {len(urls)} total.\n\n"
        summary += "Malicious URLs:\n"

        for url in malicious_urls:
            summary += f"• {url}\n"

        summary += f"\nOverall Risk Level: {overall_risk}\n"
        summary += "Recommendation: DO NOT click on the flagged URLs. Verify legitimacy through official channels."

        return summary
