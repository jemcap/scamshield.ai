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
        "content": """
        Your Royal Mail parcel is being delivered by a courier (no. 59068) but is undeliverable due to incomplete address details. Please update your address to ensure your parcel is delivered on time. If the address is not updated by 5 July, the parcel will be returned to the delivery location. 

https://royalmaiic.live/rmp

(Please reply with a “Y” and then close the current email and re-open it to activate the link, or copy the link and open it in Safari) Thank you, Royal Mail Team!
        """,
        "sender_info": "ayyyri@royalmaill.com",
    }

    try:
        result = AiScamPhishingDetector().crew().kickoff(inputs=inputs)
        print(result.raw)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")
