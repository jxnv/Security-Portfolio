# Title: Creation of a Local Hidden User Account by Registry
# ID: 460479f3-80b7-42da-9c43-2cc1d54dbccd
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-05-03
# Tags: attack.persistence, attack.t1136.001
# Description: Sysmon registry detection of a local hidden user account.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Creation of a Local Hidden User Account by Registry
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*" AND TargetObject="*$\\(Default)" AND Image="*\\lsass.exe")
    return True

def title(event):
    return "Creation of a Local Hidden User Account by Registry"

