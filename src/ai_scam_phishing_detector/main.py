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
        Your Royal Mail parcel is being delivered by a courier (no. 59068) but is undeliverable due to incomplete address details. Please update your address to ensure your parcel is delivered on time. If the address is not updated by 5 July, the parcel will be returned to the delivery location. 
        (Please reply with a “Y” and then close the current email and re-open it to activate the link, or copy the link and open it in Safari) Thank you, Royal Mail Team!',
        https://royalmaiic.live/rmp
        """ ,
        'sender_info': 'asadvas@royaailmail.com'
    }
    
    try:
        result = AiScamPhishingDetector().crew().kickoff(inputs=inputs)
        print(result.raw)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


def train():
    """
    Train the crew for a given number of iterations.
    """
    inputs = {
        "topic": "AI LLMs",
        'current_year': str(datetime.now().year)
    }
    try:
        AiScamPhishingDetector().crew().train(n_iterations=int(sys.argv[1]), filename=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        AiScamPhishingDetector().crew().replay(task_id=sys.argv[1])

    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    """
    Test the crew execution and returns the results.
    """
    inputs = {
        "topic": "AI LLMs",
        "current_year": str(datetime.now().year)
    }
    
    try:
        AiScamPhishingDetector().crew().test(n_iterations=int(sys.argv[1]), eval_llm=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")
