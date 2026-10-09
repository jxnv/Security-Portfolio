# Title: Service Reload or Start - Linux
# ID: 2625cc59-0634-40d0-821e-cb67382a3dd7
# Status: test
# Level: low
# Author: Jakob Weinzettl, oscd.community, CheraghiMilad
# Date: 2019-09-23
# Tags: attack.privilege-escalation, attack.persistence, attack.t1543.002
# Description: Detects the start, reload or restart of a service.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service Reload or Start - Linux
def rule(event):
    # Detection Logic:
    # (type="EXECVE" AND (a0="*systemctl*" OR a0="*service*") AND (a1="*reload*" OR a1="*start*"))
    return True

def title(event):
    return "Service Reload or Start - Linux"

