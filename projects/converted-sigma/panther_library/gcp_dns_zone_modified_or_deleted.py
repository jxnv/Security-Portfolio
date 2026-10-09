# Title: Google Cloud DNS Zone Modified or Deleted
# ID: 28268a8f-191f-4c17-85b2-f5aa4fa829c3
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-15
# Tags: attack.impact
# Description: Identifies when a DNS Zone is modified or deleted in Google Cloud.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Google Cloud DNS Zone Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((gcp.audit.method_name="Dns.ManagedZones.Delete" OR gcp.audit.method_name="Dns.ManagedZones.Update" OR gcp.audit.method_name="Dns.ManagedZones.Patch"))
    return True

def title(event):
    return "Google Cloud DNS Zone Modified or Deleted"

