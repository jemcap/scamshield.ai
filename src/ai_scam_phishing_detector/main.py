#!/usr/bin/env python
import sys
import warnings

from datetime import datetime

from ai_scam_phishing_detector.crew import AiScamPhishingDetector

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# This main file is intended to be a way for you to run your
# crew locally, so refrain from adding unnecessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information

def run():
    """
    Run the crew.
    """
    inputs = {
        'content': """
        We will deliver your MPB parcel today between 07:41-08:41, if not in for your driver Dylan you have options www.dpd.co.uk/b/6dQmTaJWfZo6
        """ ,
        'sender_info': 'DPD'
    }
    
    try:
        result = AiScamPhishingDetector().crew().kickoff(inputs=inputs)
        print(result.raw)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")