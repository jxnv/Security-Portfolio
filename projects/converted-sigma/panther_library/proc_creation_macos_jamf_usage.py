# Title: JAMF MDM Execution
# ID: be2e3a5c-9cc7-4d02-842a-68e9cb26ec49
# Status: test
# Level: low
# Author: Jay Pandit
# Date: 2023-08-22
# Tags: attack.execution
# Description: Detects execution of the "jamf" binary to create user accounts and run commands. For example, the binary can be abused by attackers on the system in order to bypass security controls or remove application control polices.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: JAMF MDM Execution
def rule(event):
    # Detection Logic:
    # (Image="*/jamf" AND (CommandLine="*createAccount*" OR CommandLine="*manage*" OR CommandLine="*removeFramework*" OR CommandLine="*removeMdmProfile*" OR CommandLine="*resetPassword*" OR CommandLine="*setComputerName*"))
    return True

def title(event):
    return "JAMF MDM Execution"

