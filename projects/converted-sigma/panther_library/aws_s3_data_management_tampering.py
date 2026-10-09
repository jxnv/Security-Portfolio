# Title: AWS S3 Data Management Tampering
# ID: 78b3756a-7804-4ef7-8555-7b9024a02e2d
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-07-24
# Tags: attack.exfiltration, attack.t1537
# Description: Detects when a user tampers with S3 data management in Amazon Web Services.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS S3 Data Management Tampering
def rule(event):
    # Detection Logic:
    # (eventSource="s3.amazonaws.com" AND (eventName="PutBucketLogging" OR eventName="PutBucketWebsite" OR eventName="PutEncryptionConfiguration" OR eventName="PutLifecycleConfiguration" OR eventName="PutReplicationConfiguration" OR eventName="ReplicateObject" OR eventName="RestoreObject"))
    return True

def title(event):
    return "AWS S3 Data Management Tampering"

