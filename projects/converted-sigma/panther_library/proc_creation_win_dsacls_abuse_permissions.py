# Title: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
# ID: 01c42d3c-242d-4655-85b2-34f1739632f7
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-20
# Tags: attack.stealth, attack.t1218
# Description: Detects usage of Dsacls to grant over permissive permissions
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="* /G *") AND ((Image="*\\dsacls.exe") OR (OriginalFileName="DSACLS.EXE")) AND ((CommandLine="*GR*" OR CommandLine="*GE*" OR CommandLine="*GW*" OR CommandLine="*GA*" OR CommandLine="*WP*" OR CommandLine="*WD*")))
    return True

def title(event):
    return "Potentially Over Permissive Permissions Granted Using Dsacls.EXE"

