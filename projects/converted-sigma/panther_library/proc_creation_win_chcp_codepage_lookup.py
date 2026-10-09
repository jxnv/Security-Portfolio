# Title: Console CodePage Lookup Via CHCP
# ID: 7090adee-82e2-4269-bd59-80691e7c6338
# Status: test
# Level: medium
# Author: _pete_0, TheDFIRReport
# Date: 2022-02-21
# Tags: attack.discovery, attack.t1614.001
# Description: Detects use of chcp to look up the system locale value as part of host discovery
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Console CodePage Lookup Via CHCP
def rule(event):
    # Detection Logic:
    # (ParentImage="*\\cmd.exe" AND (ParentCommandLine="* -c *" OR ParentCommandLine="* -r *" OR ParentCommandLine="* -k *") AND Image="*\\chcp.com" AND (CommandLine="*chcp" OR CommandLine="*chcp " OR CommandLine="*chcp  "))
    return True

def title(event):
    return "Console CodePage Lookup Via CHCP"

