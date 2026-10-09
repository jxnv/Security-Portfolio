# Title: Suspicious Creation with Colorcpl
# ID: e15b518d-b4ce-4410-a9cd-501f23ce4a18
# Status: test
# Level: high
# Author: frack113
# Date: 2022-01-21
# Tags: attack.stealth, attack.t1564
# Description: Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Creation with Colorcpl
def rule(event):
    # Detection Logic:
    # ((Image="*\\colorcpl.exe") AND NOT (((TargetFilename="*.icm" OR TargetFilename="*.gmmp" OR TargetFilename="*.cdmp" OR TargetFilename="*.camp"))))
    return True

def title(event):
    return "Suspicious Creation with Colorcpl"

