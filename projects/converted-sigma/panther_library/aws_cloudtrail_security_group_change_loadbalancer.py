# Title: LoadBalancer Security Group Modification
# ID: 7a4409fc-f8ca-45f6-8006-127d779eaad9
# Status: test
# Level: medium
# Author: jamesc-grafana
# Date: 2024-07-11
# Tags: attack.initial-access, attack.t1190
# Description: Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB).
# This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet controlled by the account.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: LoadBalancer Security Group Modification
def rule(event):
    # Detection Logic:
    # (eventSource="elasticloadbalancing.amazonaws.com" AND (eventName="ApplySecurityGroupsToLoadBalancer" OR eventName="SetSecurityGroups"))
    return True

def title(event):
    return "LoadBalancer Security Group Modification"

