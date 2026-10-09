# Title: Restore Public AWS RDS Instance
# ID: c3f265c7-ff03-4056-8ab2-d486227b4599
# Status: test
# Level: high
# Author: faloker
# Date: 2020-02-12
# Tags: attack.exfiltration, attack.t1020
# Description: Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Restore Public AWS RDS Instance
def rule(event):
    # Detection Logic:
    # (eventSource="rds.amazonaws.com" AND responseElements.publiclyAccessible="true" AND eventName="RestoreDBInstanceFromDBSnapshot")
    return True

def title(event):
    return "Restore Public AWS RDS Instance"

