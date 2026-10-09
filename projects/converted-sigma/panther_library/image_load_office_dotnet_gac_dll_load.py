# Title: GAC DLL Loaded Via Office Applications
# ID: 90217a70-13fc-48e4-b3db-0d836c5824ac
# Status: test
# Level: high
# Author: Antonlovesdnb
# Date: 2020-02-19
# Tags: attack.execution, attack.t1204.002
# Description: Detects any GAC DLL being loaded by an Office Product
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: GAC DLL Loaded Via Office Applications
def rule(event):
    # Detection Logic:
    # ((Image="*\\excel.exe" OR Image="*\\mspub.exe" OR Image="*\\onenote.exe" OR Image="*\\onenoteim.exe" OR Image="*\\outlook.exe" OR Image="*\\powerpnt.exe" OR Image="*\\winword.exe") AND ImageLoaded="C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL*")
    return True

def title(event):
    return "GAC DLL Loaded Via Office Applications"

