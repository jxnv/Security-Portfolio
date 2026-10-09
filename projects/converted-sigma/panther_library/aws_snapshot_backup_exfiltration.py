# Title: AWS Snapshot Backup Exfiltration
# ID: abae8fec-57bd-4f87-aff6-6e3db989843d
# Status: test
# Level: medium
# Author: Darin Smith
# Date: 2021-05-17
# Tags: attack.exfiltration, attack.t1537
# Description: Detects the modification of an EC2 snapshot's permissions to enable access from another account
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS Snapshot Backup Exfiltration
def rule(event):
    # Detection Logic:
    # (eventSource="ec2.amazonaws.com" AND eventName="ModifySnapshotAttribute")
    return True

def title(event):
    return "AWS Snapshot Backup Exfiltration"

