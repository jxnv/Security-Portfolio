# Title: Potential SMB Relay Attack Tool Execution
# ID: 5589ab4f-a767-433c-961d-c91f3f704db1
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2021-07-24
# Tags: attack.collection, attack.execution, attack.credential-access, attack.t1557.001
# Description: Detects different hacktools used for relay attacks on Windows for privilege escalation
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential SMB Relay Attack Tool Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="*.exe -c \"{*" AND CommandLine="*}\" -z") OR ((Image="*PetitPotam*" OR Image="*RottenPotato*" OR Image="*HotPotato*" OR Image="*JuicyPotato*" OR Image="*\\just_dce_*" OR Image="*Juicy Potato*" OR Image="*\\temp\\rot.exe*" OR Image="*\\Potato.exe*" OR Image="*\\SpoolSample.exe*" OR Image="*\\Responder.exe*" OR Image="*\\smbrelayx*" OR Image="*\\ntlmrelayx*" OR Image="*\\LocalPotato*")) OR ((CommandLine="*Invoke-Tater*" OR CommandLine="* smbrelay*" OR CommandLine="* ntlmrelay*" OR CommandLine="*cme smb *" OR CommandLine="* /ntlm:NTLMhash *" OR CommandLine="*Invoke-PetitPotam*" OR CommandLine="*.exe -t * -p *"))) AND NOT (((Image="*HotPotatoes6*" OR Image="*HotPotatoes7*" OR Image="*HotPotatoes *"))))
    return True

def title(event):
    return "Potential SMB Relay Attack Tool Execution"

