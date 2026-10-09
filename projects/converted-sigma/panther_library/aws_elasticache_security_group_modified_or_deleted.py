# Title: AWS ElastiCache Security Group Modified or Deleted
# ID: 7c797da2-9cf2-4523-ba64-33b06339f0cc
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-07-24
# Tags: attack.impact, attack.t1531
# Description: Identifies when an ElastiCache security group has been modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS ElastiCache Security Group Modified or Deleted
def rule(event):
    # Detection Logic:
    # (eventSource="elasticache.amazonaws.com" AND (eventName="DeleteCacheSecurityGroup" OR eventName="AuthorizeCacheSecurityGroupIngress" OR eventName="RevokeCacheSecurityGroupIngress" OR eventName="AuthorizeCacheSecurityGroupEgress" OR eventName="RevokeCacheSecurityGroupEgress"))
    return True

def title(event):
    return "AWS ElastiCache Security Group Modified or Deleted"

