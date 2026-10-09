# Title: Suspicious Schtasks Schedule Type With High Privileges
# ID: 7a02e22e-b885-4404-b38b-1ddc7e65258a
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-31
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
# Description: Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Schtasks Schedule Type With High Privileges
def rule(event):
    # Detection Logic:
    # (((Image="*\\schtasks.exe") OR (OriginalFileName="schtasks.exe")) AND ((CommandLine="*NT AUT*" OR CommandLine="* SYSTEM*" OR CommandLine="*HIGHEST*")) AND ((CommandLine="* ONLOGON *" OR CommandLine="* ONSTART *" OR CommandLine="* ONCE *" OR CommandLine="* ONIDLE *")))
    return True

def title(event):
    return "Suspicious Schtasks Schedule Type With High Privileges"

