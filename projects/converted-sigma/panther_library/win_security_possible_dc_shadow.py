# Title: Possible DC Shadow Attack
# ID: 32e19d25-4aed-4860-a55a-be99cb0bf7ed
# Status: test
# Level: medium
# Author: Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah
# Date: 2019-10-25
# Tags: attack.credential-access, attack.defense-impairment, attack.t1207
# Description: Detects DCShadow via create new SPN
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Possible DC Shadow Attack
def rule(event):
    # Detection Logic:
    # ((EventID="4742" AND ServicePrincipalNames="*GC/*") OR (EventID="5136" AND AttributeLDAPDisplayName="servicePrincipalName" AND AttributeValue="GC/*"))
    return True

def title(event):
    return "Possible DC Shadow Attack"

