# Title: User Added To Highly Privileged Group
# ID: 10fb649c-3600-4d37-b1e6-56ea90bb7e09
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-02-23
# Tags: attack.privilege-escalation, attack.persistence, attack.t1098
# Description: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: User Added To Highly Privileged Group
def rule(event):
    # Detection Logic:
    # (((CommandLine="*Group Policy Creator Owners*" OR CommandLine="*Schema Admins*")) AND (((CommandLine="*localgroup *" AND CommandLine="* /add*")) OR ((CommandLine="*Add-LocalGroupMember *" AND CommandLine="* -Group *"))))
    return True

def title(event):
    return "User Added To Highly Privileged Group"

