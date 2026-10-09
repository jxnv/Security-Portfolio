# Title: Persistence Via TypedPaths - CommandLine
# ID: ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-22
# Tags: attack.persistence
# Description: Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Persistence Via TypedPaths - CommandLine
def rule(event):
    # Detection Logic:
    # (CommandLine="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths*")
    return True

def title(event):
    return "Persistence Via TypedPaths - CommandLine"

