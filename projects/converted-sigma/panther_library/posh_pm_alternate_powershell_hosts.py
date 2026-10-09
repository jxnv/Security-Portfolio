# Title: Alternate PowerShell Hosts - PowerShell Module
# ID: 64e8e417-c19a-475a-8d19-98ea705394cc
# Status: test
# Level: medium
# Author: Roberto Rodriguez @Cyb3rWard0g
# Date: 2019-08-11
# Tags: attack.execution, attack.t1059.001
# Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Alternate PowerShell Hosts - PowerShell Module
def rule(event):
    # Detection Logic:
    # ((ContextInfo="***") AND NOT (((ContextInfo="*C:\\Windows\\system32\\dsac.exe*") OR (ContextInfo="*ConfigSyncRun.exe*") OR ((Payload="*Update-Help*" OR Payload="*Failed to update Help for the module*")) OR ((ContextInfo="*= powershell*" OR ContextInfo="*= C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell*" OR ContextInfo="*= C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell*" OR ContextInfo="*= C:/Windows/System32/WindowsPowerShell/v1.0/powershell*" OR ContextInfo="*= C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell*" OR ContextInfo="*= \\\\\\?\\?\\C:Windows\\System32\\WindowsPowerShell\\v1.0\\powershell*" OR ContextInfo="*= \\\\\\?\\?\\C:Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell*")) OR (ContextInfo="*= C:\\WINDOWS\\System32\\sdiagnhost.exe -Embedding*") OR (ContextInfo="*C:\\Windows\\system32\\wsmprovhost.exe -Embedding*"))))
    return True

def title(event):
    return "Alternate PowerShell Hosts - PowerShell Module"

