# Title: AMSI Bypass Pattern Assembly GetType
# ID: e0d6c087-2d1c-47fd-8799-3904103c5a98
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-11-09
# Tags: attack.defense-impairment, attack.t1685, attack.execution
# Description: Detects code fragments found in small and obfuscated AMSI bypass PowerShell scripts
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AMSI Bypass Pattern Assembly GetType
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*[Ref].Assembly.GetType*" AND ScriptBlockText="*SetValue($null,$true)*" AND ScriptBlockText="*NonPublic,Static*"))
    return True

def title(event):
    return "AMSI Bypass Pattern Assembly GetType"

