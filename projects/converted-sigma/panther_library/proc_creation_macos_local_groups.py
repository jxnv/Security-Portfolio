# Title: Local Groups Discovery - MacOs
# ID: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
# Status: test
# Level: informational
# Author: Ömer Günal, Alejandro Ortuno, oscd.community
# Date: 2020-10-11
# Tags: attack.discovery, attack.t1069.001
# Description: Detects enumeration of local system groups
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Local Groups Discovery - MacOs
def rule(event):
    # Detection Logic:
    # ((Image="*/dscacheutil" AND (CommandLine="*-q*" AND CommandLine="*group*")) OR (Image="*/cat" AND CommandLine="*/etc/group*") OR (Image="*/dscl" AND (CommandLine="*-list*" AND CommandLine="*/groups*")))
    return True

def title(event):
    return "Local Groups Discovery - MacOs"

