// Title: AD Groups Or Users Enumeration Using PowerShell - PoshModule
// ID: 815bfc17-7fc6-4908-a55e-2f37b98cedb4
// Status: test
// Level: low
// Author: frack113
// Date: 2021-12-15
// Tags: attack.discovery, attack.t1069.001
// Description: Adversaries may attempt to find domain-level groups and permission settings.
// The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
// Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Payload contains "get-ADPrincipalGroupMembership") or (ContextInfo contains "get-ADPrincipalGroupMembership")) or (((Payload contains "get-aduser" and Payload contains "-f " and Payload contains "-pr " and Payload contains "DoesNotRequirePreAuth")) or ((ContextInfo contains "get-aduser" and ContextInfo contains "-f " and ContextInfo contains "-pr " and ContextInfo contains "DoesNotRequirePreAuth"))))
