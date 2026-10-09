# Title: Change PowerShell Policies to an Insecure Level
# ID: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-11-01
# Tags: attack.execution, attack.t1059.001
# Description: Detects changing the PowerShell script execution policy to a potentially insecure level using the "-ExecutionPolicy" flag.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Change PowerShell Policies to an Insecure Level
def rule(event):
    # Detection Logic:
    # (((((OriginalFileName="powershell_ise.exe" OR OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll")) OR ((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))) AND ((CommandLine="*Bypass*" OR CommandLine="*Unrestricted*")) AND ((CommandLine="*-executionpolicy *" OR CommandLine="* -ep *" OR CommandLine="* -exec *"))) AND NOT (((ParentImage="C:\\Windows\\SysWOW64\\msiexec.exe" OR ParentImage="C:\\Windows\\System32\\msiexec.exe") AND (CommandLine="*-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files\\PowerShell\\7\\*" OR CommandLine="*-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files (x86)\\PowerShell\\7\\*"))) AND NOT (((ParentImage="*C:\\Program Files\\Avast Software\\Avast\\*" OR ParentImage="*C:\\Program Files (x86)\\Avast Software\\Avast\\*" OR ParentImage="*\\instup.exe*") AND (CommandLine="*-ExecutionPolicy ByPass -File \"C:\\Program Files\\Avast Software\\Avast*" OR CommandLine="*-ExecutionPolicy ByPass -File \"C:\\Program Files (x86)\\Avast Software\\Avast\\*"))))
    return True

def title(event):
    return "Change PowerShell Policies to an Insecure Level"

