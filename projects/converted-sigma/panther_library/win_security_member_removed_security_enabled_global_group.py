# Title: A Member Was Removed From a Security-Enabled Global Group
# ID: 02c39d30-02b5-45d2-b435-8aebfe5a8629
# Status: stable
# Level: low
# Author: Alexandr Yampolskyi, SOC Prime
# Date: 2023-04-26
# Tags: attack.privilege-escalation, attack.persistence, attack.t1098
# Description: Detects activity when a member is removed from a security-enabled global group
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: A Member Was Removed From a Security-Enabled Global Group
def rule(event):
    # Detection Logic:
    # ((EventID="633" OR EventID="4729"))
    return True

def title(event):
    return "A Member Was Removed From a Security-Enabled Global Group"

