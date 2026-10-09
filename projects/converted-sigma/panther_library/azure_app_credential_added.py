# Title: Added Credentials to Existing Application
# ID: cbb67ecc-fb70-4467-9350-c910bdf7c628
# Status: test
# Level: high
# Author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
# Date: 2022-05-26
# Tags: attack.privilege-escalation, attack.t1098.001, attack.persistence
# Description: Detects when a new credential is added to an existing application. Any additional credentials added outside of expected processes could be a malicious actor using those credentials.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Added Credentials to Existing Application
def rule(event):
    # Detection Logic:
    # ((properties.message="Update application - Certificates and secrets management" OR properties.message="Update Service principal/Update Application"))
    return True

def title(event):
    return "Added Credentials to Existing Application"

