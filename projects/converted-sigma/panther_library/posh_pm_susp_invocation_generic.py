# Title: Suspicious PowerShell Invocations - Generic - PowerShell Module
# ID: bbb80e91-5746-4fbe-8898-122e2cafdbf4
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2017-03-12
# Tags: attack.execution, attack.t1059.001
# Description: Detects suspicious PowerShell invocation command parameters
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Invocations - Generic - PowerShell Module
def rule(event):
    # Detection Logic:
    # (((ContextInfo="* -enc *" OR ContextInfo="* -EncodedCommand *" OR ContextInfo="* -ec *")) AND ((ContextInfo="* -w hidden *" OR ContextInfo="* -window hidden *" OR ContextInfo="* -windowstyle hidden *" OR ContextInfo="* -w 1 *")) AND ((ContextInfo="* -noni *" OR ContextInfo="* -noninteractive *")))
    return True

def title(event):
    return "Suspicious PowerShell Invocations - Generic - PowerShell Module"

