# Title: Suspicious Execution of InstallUtil Without Log
# ID: d042284c-a296-4988-9be5-f424fadcc28c
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-01-23
# Tags: attack.stealth
# Description: Uses the .NET InstallUtil.exe application in order to execute image without log
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Execution of InstallUtil Without Log
def rule(event):
    # Detection Logic:
    # (Image="*\\InstallUtil.exe" AND Image="*Microsoft.NET\\Framework*" AND (CommandLine="*/logfile= *" AND CommandLine="*/LogToConsole=false*"))
    return True

def title(event):
    return "Suspicious Execution of InstallUtil Without Log"

