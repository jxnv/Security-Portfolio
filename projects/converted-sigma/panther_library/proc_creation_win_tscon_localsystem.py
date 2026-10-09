# Title: Suspicious TSCON Start as SYSTEM
# ID: 9847f263-4a81-424f-970c-875dab15b79b
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2018-03-17
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects a tscon.exe start as LOCAL SYSTEM
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious TSCON Start as SYSTEM
def rule(event):
    # Detection Logic:
    # ((User="*AUTHORI*" OR User="*AUTORI*") AND Image="*\\tscon.exe")
    return True

def title(event):
    return "Suspicious TSCON Start as SYSTEM"

