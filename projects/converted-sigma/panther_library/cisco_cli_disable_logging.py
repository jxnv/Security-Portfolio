# Title: Cisco Disabling Logging
# ID: 9e8f6035-88bf-4a63-96b6-b17c0508257e
# Status: test
# Level: high
# Author: Austin Clark
# Date: 2019-08-11
# Tags: attack.defense-impairment, attack.t1685
# Description: Turn off logging locally or remote
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cisco Disabling Logging
def rule(event):
    # Detection Logic:
    # ("no logging" OR "no aaa new-model")
    return True

def title(event):
    return "Cisco Disabling Logging"

