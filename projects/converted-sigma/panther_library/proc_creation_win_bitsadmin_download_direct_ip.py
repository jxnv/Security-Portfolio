# Title: Suspicious Download From Direct IP Via Bitsadmin
# ID: 99c840f2-2012-46fd-9141-c761987550ef
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-06-28
# Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003
# Description: Detects usage of bitsadmin downloading a file using an URL that contains an IP
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Download From Direct IP Via Bitsadmin
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*://1*" OR CommandLine="*://2*" OR CommandLine="*://3*" OR CommandLine="*://4*" OR CommandLine="*://5*" OR CommandLine="*://6*" OR CommandLine="*://7*" OR CommandLine="*://8*" OR CommandLine="*://9*")) AND ((CommandLine="* /transfer *" OR CommandLine="* /create *" OR CommandLine="* /addfile *")) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName="bitsadmin.exe"))) AND NOT ((CommandLine="*://7-*")))
    return True

def title(event):
    return "Suspicious Download From Direct IP Via Bitsadmin"

