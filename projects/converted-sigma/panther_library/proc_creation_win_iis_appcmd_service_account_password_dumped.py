# Title: Microsoft IIS Service Account Password Dumped
# ID: 2d3cdeec-c0db-45b4-aa86-082f7eb75701
# Status: test
# Level: high
# Author: Tim Rauch, Janantha Marasinghe, Elastic (original idea)
# Date: 2022-11-08
# Tags: attack.credential-access, attack.t1003
# Description: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Microsoft IIS Service Account Password Dumped
def rule(event):
    # Detection Logic:
    # (((CommandLine="*list *") AND ((Image="*\\appcmd.exe") OR (OriginalFileName="appcmd.exe"))) AND (((CommandLine="* /config*" OR CommandLine="* /xml*" OR CommandLine="* -config*" OR CommandLine="* -xml*")) OR (((CommandLine="* /@t*" OR CommandLine="* /text*" OR CommandLine="* /show*" OR CommandLine="* -@t*" OR CommandLine="* -text*" OR CommandLine="* -show*")) AND ((CommandLine="*:\\**" OR CommandLine="*password*")))))
    return True

def title(event):
    return "Microsoft IIS Service Account Password Dumped"

