# Title: Start of NT Virtual DOS Machine
# ID: 16905e21-66ee-42fe-b256-1318ada2d770
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-07-16
# Tags: attack.stealth
# Description: Ntvdm.exe allows the execution of 16-bit Windows applications on 32-bit Windows operating systems, as well as the execution of both 16-bit and 32-bit DOS applications
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Start of NT Virtual DOS Machine
def rule(event):
    # Detection Logic:
    # ((Image="*\\ntvdm.exe" OR Image="*\\csrstub.exe"))
    return True

def title(event):
    return "Start of NT Virtual DOS Machine"

