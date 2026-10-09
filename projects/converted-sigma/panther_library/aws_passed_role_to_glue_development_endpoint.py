# Title: AWS Glue Development Endpoint Activity
# ID: 4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-10-03
# Tags: attack.privilege-escalation
# Description: Detects possible suspicious glue development endpoint activity.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS Glue Development Endpoint Activity
def rule(event):
    # Detection Logic:
    # (eventSource="glue.amazonaws.com" AND (eventName="CreateDevEndpoint" OR eventName="DeleteDevEndpoint" OR eventName="UpdateDevEndpoint"))
    return True

def title(event):
    return "AWS Glue Development Endpoint Activity"

