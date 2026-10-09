# Title: PsExec/PAExec Escalation to LOCAL SYSTEM
# ID: 8834e2f7-6b4b-4f09-8906-d2276470ee23
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
# Date: 2021-11-23
# Tags: attack.resource-development, attack.t1587.001
# Description: Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PsExec/PAExec Escalation to LOCAL SYSTEM
def rule(event):
    # Detection Logic:
    # (((CommandLine="*psexec*" OR CommandLine="*paexec*" OR CommandLine="*accepteula*")) AND ((CommandLine="* -s cmd*" OR CommandLine="* -s -i cmd*" OR CommandLine="* -i -s cmd*" OR CommandLine="* -s pwsh*" OR CommandLine="* -s -i pwsh*" OR CommandLine="* -i -s pwsh*" OR CommandLine="* -s powershell*" OR CommandLine="* -s -i powershell*" OR CommandLine="* -i -s powershell*")))
    return True

def title(event):
    return "PsExec/PAExec Escalation to LOCAL SYSTEM"

