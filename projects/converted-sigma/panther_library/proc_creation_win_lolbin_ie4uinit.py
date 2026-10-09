# Title: Ie4uinit Lolbin Use From Invalid Path
# ID: d3bf399f-b0cf-4250-8bb4-dfc192ab81dc
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-05-07
# Tags: attack.stealth, attack.t1218
# Description: Detect use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Ie4uinit Lolbin Use From Invalid Path
def rule(event):
    # Detection Logic:
    # (((Image="*\\ie4uinit.exe") OR (OriginalFileName="IE4UINIT.EXE")) AND NOT ((((CurrentDirectory="c:\\windows\\system32\\" OR CurrentDirectory="c:\\windows\\sysWOW64\\")) OR (NOT CurrentDirectory=*))))
    return True

def title(event):
    return "Ie4uinit Lolbin Use From Invalid Path"

