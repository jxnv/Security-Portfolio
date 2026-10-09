# Title: Important Windows Service Terminated Unexpectedly
# ID: 56abae0c-6212-4b97-adc0-0b559bb950c3
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-04-14
# Tags: attack.stealth
# Description: Detects important or interesting Windows services that got terminated unexpectedly.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Important Windows Service Terminated Unexpectedly
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7034") AND ((param1="*Message Queuing*") OR ((Binary="*4d0053004d005100*" OR Binary="*6d0073006d007100*"))))
    return True

def title(event):
    return "Important Windows Service Terminated Unexpectedly"

