# Title: NET NGenAssemblyUsageLog Registry Key Tamper
# ID: 28036918-04d3-423d-91c0-55ecf99fb892
# Status: test
# Level: high
# Author: frack113
# Date: 2022-11-18
# Tags: attack.persistence, attack.defense-impairment, attack.t1112
# Description: Detects changes to the NGenAssemblyUsageLog registry key.
# .NET Usage Log output location can be controlled by setting the NGenAssemblyUsageLog CLR configuration knob in the Registry or by configuring an environment variable (as described in the next section).
# By simplify specifying an arbitrary value (e.g. fake output location or junk data) for the expected value, a Usage Log file for the .NET execution context will not be created.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: NET NGenAssemblyUsageLog Registry Key Tamper
def rule(event):
    # Detection Logic:
    # (TargetObject="*SOFTWARE\\Microsoft\\.NETFramework\\NGenAssemblyUsageLog")
    return True

def title(event):
    return "NET NGenAssemblyUsageLog Registry Key Tamper"

