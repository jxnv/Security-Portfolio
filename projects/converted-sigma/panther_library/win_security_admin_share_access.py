# Title: Access To ADMIN$ Network Share
# ID: 098d7118-55bc-4912-a836-dc6483a8d150
# Status: test
# Level: low
# Author: Florian Roth (Nextron Systems)
# Date: 2017-03-04
# Tags: attack.lateral-movement, attack.t1021.002
# Description: Detects access to ADMIN$ network share
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Access To ADMIN$ Network Share
def rule(event):
    # Detection Logic:
    # ((EventID="5140" AND ShareName="Admin$") AND NOT ((SubjectUserName="*$")))
    return True

def title(event):
    return "Access To ADMIN$ Network Share"

