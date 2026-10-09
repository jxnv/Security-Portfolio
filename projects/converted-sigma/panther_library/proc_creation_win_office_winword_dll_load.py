# Title: Potential Arbitrary DLL Load Using Winword
# ID: f7375e28-5c14-432f-b8d1-1db26c832df3
# Status: test
# Level: medium
# Author: Victor Sergeev, oscd.community
# Date: 2020-10-09
# Tags: attack.stealth, attack.t1202
# Description: Detects potential DLL sideloading using the Microsoft Office winword process via the '/l' flag.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Arbitrary DLL Load Using Winword
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/l *" AND CommandLine="*.dll*")) AND ((Image="*\\WINWORD.exe") OR (OriginalFileName="WinWord.exe")))
    return True

def title(event):
    return "Potential Arbitrary DLL Load Using Winword"

