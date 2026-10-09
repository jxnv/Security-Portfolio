# Title: Windows Registry Trust Record Modification
# ID: 295a59c1-7b79-4b47-a930-df12c15fc9c2
# Status: test
# Level: medium
# Author: Antonlovesdnb, Trent Liffick (@tliffick)
# Date: 2020-02-19
# Tags: attack.initial-access, attack.t1566.001
# Description: Alerts on trust record modification within the registry, indicating usage of macros
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Registry Trust Record Modification
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Security\\Trusted Documents\\TrustRecords*")
    return True

def title(event):
    return "Windows Registry Trust Record Modification"

