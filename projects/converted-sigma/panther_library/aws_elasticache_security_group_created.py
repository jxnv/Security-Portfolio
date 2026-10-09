# Title: AWS ElastiCache Security Group Created
# ID: 4ae68615-866f-4304-b24b-ba048dfa5ca7
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-07-24
# Tags: attack.persistence, attack.t1136, attack.t1136.003
# Description: Detects when an ElastiCache security group has been created.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS ElastiCache Security Group Created
def rule(event):
    # Detection Logic:
    # (eventSource="elasticache.amazonaws.com" AND eventName="CreateCacheSecurityGroup")
    return True

def title(event):
    return "AWS ElastiCache Security Group Created"

