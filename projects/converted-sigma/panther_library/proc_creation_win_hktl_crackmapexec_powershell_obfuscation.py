# Title: HackTool - CrackMapExec PowerShell Obfuscation
# ID: 6f8b3439-a203-45dc-a88b-abf57ea15ccf
# Status: test
# Level: high
# Author: Thomas Patzke
# Date: 2020-05-22
# Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027.005
# Description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - CrackMapExec PowerShell Obfuscation
def rule(event):
    # Detection Logic:
    # (((CommandLine="*join*split*" OR CommandLine="*( $ShellId[1]+$ShellId[13]+'x')*" OR CommandLine="*( $PSHome[*]+$PSHOME[*]+*" OR CommandLine="*( $env:Public[13]+$env:Public[5]+'x')*" OR CommandLine="*( $env:ComSpec[4,*,25]-Join'')*" OR CommandLine="*[1,3]+'x'-Join'')*")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))))
    return True

def title(event):
    return "HackTool - CrackMapExec PowerShell Obfuscation"

