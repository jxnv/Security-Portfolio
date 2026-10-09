# Title: Indicator Removal on Host - Clear Mac System Logs
# ID: acf61bd8-d814-4272-81f0-a7a269aa69aa
# Status: test
# Level: medium
# Author: remotephone, oscd.community
# Date: 2020-10-11
# Tags: attack.defense-impairment, attack.t1685.006
# Description: Detects deletion of local audit logs
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Indicator Removal on Host - Clear Mac System Logs
def rule(event):
    # Detection Logic:
    # (((Image="*/rm" OR Image="*/unlink" OR Image="*/shred")) AND ((CommandLine="*/var/log*") OR ((CommandLine="*/Users/*" AND CommandLine="*/Library/Logs/*"))))
    return True

def title(event):
    return "Indicator Removal on Host - Clear Mac System Logs"

