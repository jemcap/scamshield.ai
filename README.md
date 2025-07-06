# AI Scam & Phishing Detector

An advanced multi-agent AI system powered by [crewAI](https://crewai.com) that analyzes messages, emails, and communications to detect scams and phishing attempts. The system uses specialized AI agents working collaboratively to extract information, check reputations, detect patterns, and assess threats.

## 🚀 Features

### 🤖 AI Agents
- **Content Analyzer**: Extracts emails, phone numbers, URLs and analyzes message content
- **Pattern Detector**: Identifies scam patterns and performs reputation checks  
- **Threat Assessor**: Evaluates threat levels and provides risk scores

### 🛠️ Advanced Tools
- **ReputationSearchTool**: Deep web search using SerperDevTool to check if emails, phone numbers, domains have been flagged as scams
- **LinkAnalysisTool**: 🆕 Comprehensive URL extraction and analysis tool that:
  - Extracts all URLs from message content
  - Checks for malicious patterns and phishing indicators
  - Analyzes domain safety and reputation
  - Detects URL shorteners and expands them
  - Performs deep web searches for URL reputation
  - Provides risk assessment (LOW, MEDIUM, HIGH, CRITICAL)
- **ExtractEmailTool**: Extracts and validates email addresses, identifies suspicious patterns
- **ExtractPhoneNumbersTool**: Extracts phone numbers with carrier and location information
- **ExtractUrlTool**: Extracts URLs and analyzes domains for suspicious indicators

### 🔍 Automated Scammer Detection
The system automatically flags senders as scammers if their contact information (email, phone, domain) has been reported in scam databases or complaint sites.

## 📋 Prerequisites

- Python >=3.10 <3.14
- OpenAI API Key
- Serper API Key (for web search functionality)

## 🛠️ Installation

1. **Install UV** (if not already installed):
```bash
pip install uv
```

2. **Navigate to project directory and install dependencies**:
```bash
crewai install
```

3. **Set up environment variables**:
   - Copy `.env.example` to `.env`
   - Add your API keys:
```bash
OPENAI_API_KEY=your_openai_api_key_here
SERPER_API_KEY=your_serper_api_key_here
```

### 🔑 Getting API Keys

- **OpenAI API Key**: Get from [OpenAI Platform](https://platform.openai.com/)
- **Serper API Key**: Get from [Serper.dev](https://serper.dev/) (free tier available)

## 🚀 Usage

### Running the Main System
```bash
crewai run
```

### Testing the Reputation Tool
```bash
python test_reputation_tool.py
```

## 📊 How It Works

1. **Content Analysis**: The Content Analyzer extracts all contact information (emails, phone numbers, URLs) and analyzes message content for suspicious patterns.

2. **Reputation Checking**: The Pattern Detector uses the ReputationSearchTool to search the web for any reports of the extracted contact information being involved in scams.

3. **Threat Assessment**: The Threat Assessor evaluates all findings and assigns a risk level, automatically flagging known scammers.

### 🔍 Reputation Search Process

The ReputationSearchTool performs comprehensive searches across:
- Scam reporting sites (scammer.info, 419eater.com, etc.)
- Consumer complaint platforms
- Forum discussions about scams
- Blacklist databases

**Risk Levels**:
- **HIGH**: 5+ flags or strong evidence of malicious activity → **AUTOMATIC SCAMMER CLASSIFICATION**
- **MEDIUM**: 2-4 flags or moderate evidence
- **LOW**: 1-2 flags or minor concerns  
- **UNKNOWN**: No flags found

## 📁 Project Structure

```
src/ai_scam_phishing_detector/
├── config/
│   ├── agents.yaml          # Agent configurations
│   └── tasks.yaml           # Task definitions
├── tools/
│   ├── search_reputation_tool.py    # 🆕 Reputation search with SerperDevTool
│   ├── extract_email_addresses_tool.py
│   ├── extract_phone_numbers_tool.py
│   └── extract_url_tool.py
├── crew.py                  # Main crew orchestration
└── main.py                  # Entry point
```

## 🎯 Customization

- **Agents**: Modify `config/agents.yaml` to customize agent behavior
- **Tasks**: Update `config/tasks.yaml` to define custom analysis workflows  
- **Tools**: Extend or modify tools in the `tools/` directory
- **Logic**: Customize crew orchestration in `crew.py`

## 📈 Output

The system generates a comprehensive threat assessment report (`output/threat_assessment.md`) containing:
- Risk level and score
- Detailed reputation findings
- Scam pattern analysis  
- Recommended actions
- Evidence from web searches

## 🧪 Testing

Test individual components:

```bash
# Test reputation tool
python test_reputation_tool.py

# Test link analysis tool
python test_link_analysis_tool.py

# Test extraction tools (examples)
python -c "from src.ai_scam_phishing_detector.tools import ReputationSearchTool; print(ReputationSearchTool()._run('suspicious@fake-bank.com'))"
```

## 🔒 Security & Privacy

- All searches are performed through legitimate APIs
- No personal data is stored permanently
- API keys should be kept secure and not committed to version control

## 🤝 Support

For support, questions, or feedback:
- Visit [crewAI documentation](https://docs.crewai.com)
- Check the [crewAI GitHub repository](https://github.com/joaomdmoura/crewai)
- [Join the Discord community](https://discord.com/invite/X4JWnZnxPb)

## 🚨 Disclaimer

This tool is designed to assist in identifying potential scams and phishing attempts. Always exercise caution and verify findings independently. The tool's effectiveness depends on the quality of available data and may not catch all threats.

---

**Stay safe online! 🛡️**
