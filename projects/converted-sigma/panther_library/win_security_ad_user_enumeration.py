# Title: Potential AD User Enumeration From Non-Machine Account
# ID: ab6bffca-beff-4baa-af11-6733f296d57a
# Status: test
# Level: medium
# Author: Maxime Thiebaut (@0xThiebaut)
# Date: 2020-03-30
# Tags: attack.discovery, attack.t1087.002
# Description: Detects read access to a domain user from a non-machine account
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential AD User Enumeration From Non-Machine Account
def rule(event):
    # Detection Logic:
    # ((EventID="4662" AND ObjectType="*bf967aba-0de6-11d0-a285-00aa003049e2*" AND (AccessMask="*1?" OR AccessMask="*3?" OR AccessMask="*4?" OR AccessMask="*7?" OR AccessMask="*9?" OR AccessMask="*B?" OR AccessMask="*D?" OR AccessMask="*F?")) AND NOT (((SubjectUserName="*$") OR (SubjectUserName="MSOL_*"))))
    return True

def title(event):
    return "Potential AD User Enumeration From Non-Machine Account"

