# Title: AWS EKS Cluster Created or Deleted
# ID: 33d50d03-20ec-4b74-a74e-1e65a38af1c0
# Status: test
# Level: low
# Author: Austin Songer
# Date: 2021-08-16
# Tags: attack.impact, attack.t1485
# Description: Identifies when an EKS cluster is created or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS EKS Cluster Created or Deleted
def rule(event):
    # Detection Logic:
    # (eventSource="eks.amazonaws.com" AND (eventName="CreateCluster" OR eventName="DeleteCluster"))
    return True

def title(event):
    return "AWS EKS Cluster Created or Deleted"

