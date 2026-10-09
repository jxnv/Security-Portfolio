# Title: A Security-Enabled Global Group Was Deleted
# ID: b237c54b-0f15-4612-a819-44b735e0de27
# Status: stable
# Level: low
# Author: Alexandr Yampolskyi, SOC Prime
# Date: 2023-04-26
# Tags: attack.privilege-escalation, attack.persistence, attack.t1098
# Description: Detects activity when a security-enabled global group is deleted
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: A Security-Enabled Global Group Was Deleted
def rule(event):
    # Detection Logic:
    # ((EventID="4730" OR EventID="634"))
    return True

def title(event):
    return "A Security-Enabled Global Group Was Deleted"

