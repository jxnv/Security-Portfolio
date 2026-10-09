# Title: HackTool - SharpUp PrivEsc Tool Execution
# ID: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2022-08-20
# Tags: attack.persistence, attack.privilege-escalation, attack.discovery, attack.execution, attack.stealth, attack.t1615, attack.t1569.002, attack.t1574.005
# Description: Detects the use of SharpUp, a tool for local privilege escalation
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - SharpUp PrivEsc Tool Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\SharpUp.exe") OR (Description="SharpUp") OR ((CommandLine="*HijackablePaths*" OR CommandLine="*UnquotedServicePath*" OR CommandLine="*ProcessDLLHijack*" OR CommandLine="*ModifiableServiceBinaries*" OR CommandLine="*ModifiableScheduledTask*" OR CommandLine="*DomainGPPPassword*" OR CommandLine="*CachedGPPPassword*")))
    return True

def title(event):
    return "HackTool - SharpUp PrivEsc Tool Execution"

