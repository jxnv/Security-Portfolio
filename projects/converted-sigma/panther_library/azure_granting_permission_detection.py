# Title: Granting Of Permissions To An Account
# ID: a622fcd2-4b5a-436a-b8a2-a4171161833c
# Status: test
# Level: medium
# Author: sawwinnnaung
# Date: 2020-05-07
# Tags: attack.privilege-escalation, attack.persistence, attack.t1098.003
# Description: Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Granting Of Permissions To An Account
def rule(event):
    # Detection Logic:
    # ("Microsoft.Authorization/roleAssignments/write")
    return True

def title(event):
    return "Granting Of Permissions To An Account"

