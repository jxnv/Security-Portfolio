# Title: GCP Access Policy Deleted
# ID: 32438676-1dba-4ac7-bf69-b86cba995e05
# Status: test
# Level: medium
# Author: Bryan Lim
# Date: 2024-01-12
# Tags: attack.persistence, attack.privilege-escalation, attack.t1098
# Description: Detects when an access policy that is applied to a GCP cloud resource is deleted.
# An adversary would be able to remove access policies to gain access to a GCP cloud resource.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: GCP Access Policy Deleted
def rule(event):
    # Detection Logic:
    # ((data.protoPayload.authorizationInfo.permission="accesscontextmanager.accessPolicies.delete" OR data.protoPayload.authorizationInfo.permission="accesscontextmanager.accessPolicies.accessLevels.delete" OR data.protoPayload.authorizationInfo.permission="accesscontextmanager.accessPolicies.accessZones.delete" OR data.protoPayload.authorizationInfo.permission="accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete") AND data.protoPayload.authorizationInfo.granted="true" AND data.protoPayload.serviceName="accesscontextmanager.googleapis.com")
    return True

def title(event):
    return "GCP Access Policy Deleted"

