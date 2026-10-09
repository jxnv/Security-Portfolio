// Title: Possible DC Shadow Attack
// ID: 32e19d25-4aed-4860-a55a-be99cb0bf7ed
// Status: test
// Level: medium
// Author: Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah
// Date: 2019-10-25
// Tags: attack.credential-access, attack.defense-impairment, attack.t1207
// Description: Detects DCShadow via create new SPN
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4742 and ServicePrincipalNames contains "GC/") or (EventID = 5136 and AttributeLDAPDisplayName = "servicePrincipalName" and AttributeValue startswith "GC/"))
