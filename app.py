#!/usr/bin/env python3
"""
Simple launcher script for the Gradio interface
"""

import subprocess
import sys
import os

def main():
    """Launch the Gradio interface"""
    
    print("Launching AI Scam & Phishing Detector Interface...")
    try:
        # Run the gradio interface
        subprocess.run([sys.executable, "gradio_interface.py"], check=True)
    except KeyboardInterrupt:
        print("\nInterface stopped by user.")
    except subprocess.CalledProcessError as e:
        print(f"Error running interface: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
