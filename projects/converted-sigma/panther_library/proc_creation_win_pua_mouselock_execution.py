# Title: PUA - Mouse Lock Execution
# ID: c9192ad9-75e5-43eb-8647-82a0a5b493e3
# Status: test
# Level: medium
# Author: Cian Heasley
# Date: 2020-08-13
# Tags: attack.credential-access, attack.collection, attack.t1056.002
# Description: In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - Mouse Lock Execution
def rule(event):
    # Detection Logic:
    # ((Product="*Mouse Lock*") OR (Company="*Misc314*") OR (CommandLine="*Mouse Lock_*"))
    return True

def title(event):
    return "PUA - Mouse Lock Execution"

