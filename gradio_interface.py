#!/usr/bin/env python3
"""
Gradio Web Interface for AI Scam & Phishing Detector
A simple web interface to analyze suspicious messages and get threat assessments.
"""

import gradio as gr
import os
import sys
from pathlib import Path

# Add the src directory to the path so we can import our modules
current_dir = Path(__file__).parent
src_path = current_dir / "src"
sys.path.insert(0, str(src_path))

from ai_scam_phishing_detector.crew import AiScamPhishingDetector


def analyze_message(content, sender_info):
    """
    Analyze a suspicious message using the AI crew.
    
    Args:
        content (str): The message content to analyze
        sender_info (str): Information about the sender (email, phone, name, etc.)
    
    Returns:
        tuple: (threat_assessment, status_message)
    """
    try:
        # Validate inputs
        if not content.strip():
            return "", "Error: Message content cannot be empty!"
        
        if not sender_info.strip():
            return "", "Error: Sender information cannot be empty!"
        
        # Prepare inputs for the crew
        inputs = {
            'content': content.strip(),
            'sender_info': sender_info.strip()
        }
        
        # Update status
        status = "Analyzing message... This may take a few minutes."
        yield "", status
        
        # Run the AI crew analysis
        crew = AiScamPhishingDetector()
        result = crew.crew().kickoff(inputs=inputs)
        
        # Extract the threat assessment from the crew result
        threat_assessment = result.raw if hasattr(result, 'raw') else str(result)
        
        # Success status
        status = "Analysis complete! Review the threat assessment below."
        
        yield threat_assessment, status
        
    except Exception as e:
        error_msg = f"Error during analysis: {str(e)}"
        yield "", error_msg


def create_interface():
    """Create and configure the Gradio interface."""
    
    # Custom CSS for better styling
    css = """
    .gradio-container {
        max-width: 1200px !important;
        margin: auto !important;
    }
    .gr-textbox {
        font-family: 'Monaco', 'Menlo', 'Consolas', monospace !important;
    }
    .threat-high {
        background-color: #fee !important;
        border-left: 4px solid #e74c3c !important;
        padding: 10px !important;
    }
    .threat-medium {
        background-color: #fef5e7 !important;
        border-left: 4px solid #f39c12 !important;
        padding: 10px !important;
    }
    .threat-low {
        background-color: #eafaf1 !important;
        border-left: 4px solid #27ae60 !important;
        padding: 10px !important;
    }
    """
    
    # Create the interface
    with gr.Blocks(
        title="AI Scam & Phishing Detector",
        theme=gr.themes.Soft(),
        css=css
    ) as interface:
        
        # Header
        gr.Markdown("""
        # scamshield.ai | AI Scam & Phishing Detector
        
        **Analyse suspicious messages, emails, and communications for potential scams and phishing attempts.**
        
        This AI-powered system uses multiple specialized agents to:
        - Extract and analyse URLs for malicious content
        - Check sender reputation across the web
        - Detect scam patterns and social engineering tactics
        - Provide comprehensive threat assessments
        """)
        
        # Input section
        with gr.Row():
            with gr.Column(scale=2):
                gr.Markdown("### Message to Analyze")
                content_input = gr.Textbox(
                    label="Message Content",
                    placeholder="""Paste the suspicious message here...
                    
Example:
Your account has been suspended. Click here to verify: https://suspicious-link.com/verify
Please confirm your details within 24 hours or your account will be permanently closed.""",
                    lines=8,
                    max_lines=15
                )
                
                sender_input = gr.Textbox(
                    label="Sender Information",
                    placeholder="Enter sender email, phone number, name, or any identifying information...",
                    lines=2
                )
                
                # Analyze button
                analyze_btn = gr.Button(
                    "🔍 Analyze Message", 
                    variant="primary",
                    size="lg"
                )
        
        # Status message
        status_output = gr.Markdown(
            label="Status",
            value="👆 Enter a message and sender information above, then click 'Analyze Message' to begin."
        )
        
        # Results section
        gr.Markdown("---")
        gr.Markdown("## Threat Assessment Results")
        
        threat_output = gr.Textbox(
            label="Threat Assessment Report",
            lines=20,
            max_lines=30,
            show_copy_button=True,
            interactive=False,
            placeholder="Threat assessment will appear here after analysis..."
        )
        
        
        # Event handlers
        analyze_btn.click(
            fn=analyze_message,
            inputs=[content_input, sender_input],
            outputs=[threat_output, status_output],
            show_progress=True
        )
        
        # Auto-clear button functionality
        def clear_inputs():
            return "", "", "", "Enter a new message above to analyze."
        
        clear_btn = gr.Button("Clear All", variant="secondary")
        clear_btn.click(
            fn=clear_inputs,
            outputs=[content_input, sender_input, threat_output, status_output]
        )
    
    return interface


def main():
    """Main function to launch the Gradio interface."""
    
    # Check for required environment variables
    required_env_vars = ['OPENAI_API_KEY', 'SERPER_API_KEY']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print("⚠️  Warning: Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these in your .env file before running the interface.")
        print("The application may not work correctly without them.")
        print()
    
    # Create and launch the interface
    interface = create_interface()
    
    print("🚀 Starting AI Scam & Phishing Detector Web Interface...")
    print("📡 The interface will be available at: http://localhost:7860")
    print("🛑 Press Ctrl+C to stop the server")
    print()
    
    # Launch with specific settings
    interface.launch(
        server_name="0.0.0.0",  # Allow external access
        server_port=7860,       # Default Gradio port
        share=False,            # Set to True if you want a public shareable link
        show_error=True,        # Show detailed error messages
        quiet=False             # Show startup logs
    )


if __name__ == "__main__":
    main()
