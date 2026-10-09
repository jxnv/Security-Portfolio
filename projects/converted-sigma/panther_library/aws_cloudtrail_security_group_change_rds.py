# Title: RDS Database Security Group Modification
# ID: 14f3f1c8-02d5-43a2-a191-91ffb52d3015
# Status: test
# Level: medium
# Author: jamesc-grafana
# Date: 2024-07-11
# Tags: attack.initial-access, attack.t1190
# Description: Detects changes to the security group entries for RDS databases.
# This can indicate that a misconfiguration has occurred which potentially exposes the database to the public internet, a wider audience within the VPC or that removal of valid rules has occurred which could impact the availability of the database to legitimate services and users.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: RDS Database Security Group Modification
def rule(event):
    # Detection Logic:
    # (eventSource="rds.amazonaws.com" AND (eventName="AuthorizeDBSecurityGroupIngress" OR eventName="CreateDBSecurityGroup" OR eventName="DeleteDBSecurityGroup" OR eventName="RevokeDBSecurityGroupIngress"))
    return True

def title(event):
    return "RDS Database Security Group Modification"

