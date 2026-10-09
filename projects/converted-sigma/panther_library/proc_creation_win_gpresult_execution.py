# Title: Gpresult Display Group Policy Information
# ID: e56d3073-83ff-4021-90fe-c658e0709e72
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-05-01
# Tags: attack.discovery, attack.t1615
# Description: Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Gpresult Display Group Policy Information
def rule(event):
    # Detection Logic:
    # (Image="*\\gpresult.exe" AND (CommandLine="*/z*" OR CommandLine="*/v*"))
    return True

def title(event):
    return "Gpresult Display Group Policy Information"

