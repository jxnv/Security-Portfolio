# Title: Dumping Process via Sqldumper.exe
# ID: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
# Status: test
# Level: medium
# Author: Kirill Kiryanov, oscd.community
# Date: 2020-10-08
# Tags: attack.credential-access, attack.t1003.001
# Description: Detects process dump via legitimate sqldumper.exe binary
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Dumping Process via Sqldumper.exe
def rule(event):
    # Detection Logic:
    # (Image="*\\sqldumper.exe" AND (CommandLine="*0x0110*" OR CommandLine="*0x01100:40*"))
    return True

def title(event):
    return "Dumping Process via Sqldumper.exe"

