# Title: Potential Bucket Enumeration on AWS
# ID: f305fd62-beca-47da-ad95-7690a0620084
# Status: test
# Level: low
# Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io
# Date: 2023-01-06
# Tags: attack.discovery, attack.t1580, attack.t1619
# Description: Looks for potential enumeration of AWS buckets via ListBuckets.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Bucket Enumeration on AWS
def rule(event):
    # Detection Logic:
    # ((eventSource="s3.amazonaws.com" AND eventName="ListBuckets") AND NOT ((userIdentity.type="AssumedRole")))
    return True

def title(event):
    return "Potential Bucket Enumeration on AWS"

