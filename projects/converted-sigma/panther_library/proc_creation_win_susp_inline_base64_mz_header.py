# Title: Base64 MZ Header In CommandLine
# ID: 22e58743-4ac8-4a9f-bf19-00a0428d8c5f
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-12
# Tags: attack.execution
# Description: Detects encoded base64 MZ header in the commandline
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Base64 MZ Header In CommandLine
def rule(event):
    # Detection Logic:
    # ((CommandLine="*TVqQAAMAAAAEAAAA*" OR CommandLine="*TVpQAAIAAAAEAA8A*" OR CommandLine="*TVqAAAEAAAAEABAA*" OR CommandLine="*TVoAAAAAAAAAAAAA*" OR CommandLine="*TVpTAQEAAAAEAAAA*"))
    return True

def title(event):
    return "Base64 MZ Header In CommandLine"

