# Title: Run PowerShell Script from Redirected Input Stream
# ID: c83bf4b5-cdf0-437c-90fa-43d734f7c476
# Status: test
# Level: high
# Author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
# Date: 2020-10-17
# Tags: attack.execution, attack.t1059
# Description: Detects PowerShell script execution via input stream redirect
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Run PowerShell Script from Redirected Input Stream
def rule(event):
    # Detection Logic:
    # ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND CommandLine=regex("\\s-\\s*<"))
    return True

def title(event):
    return "Run PowerShell Script from Redirected Input Stream"

