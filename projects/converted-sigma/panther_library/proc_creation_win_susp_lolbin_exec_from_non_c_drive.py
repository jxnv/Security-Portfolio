# Title: LOLBIN Execution From Abnormal Drive
# ID: d4ca7c59-e9e4-42d8-bf57-91a776efcb87
# Status: test
# Level: medium
# Author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Angelo Violetti - SEC Consult '@angelo_violetti', Aaron Herman
# Date: 2022-01-25
# Tags: attack.stealth
# Description: Detects LOLBINs executing from an abnormal or uncommon drive such as a mounted ISO.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: LOLBIN Execution From Abnormal Drive
def rule(event):
    # Detection Logic:
    # ((((Image="*\\calc.exe" OR Image="*\\certutil.exe" OR Image="*\\cmstp.exe" OR Image="*\\cscript.exe" OR Image="*\\installutil.exe" OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((OriginalFileName="CALC.EXE" OR OriginalFileName="CertUtil.exe" OR OriginalFileName="CMSTP.EXE" OR OriginalFileName="cscript.exe" OR OriginalFileName="installutil.exe" OR OriginalFileName="MSHTA.EXE" OR OriginalFileName="REGSVR32.EXE" OR OriginalFileName="RUNDLL32.EXE" OR OriginalFileName="wscript.exe"))) AND NOT (((CurrentDirectory="*C:\\*") OR (CurrentDirectory="") OR (NOT CurrentDirectory=*))))
    return True

def title(event):
    return "LOLBIN Execution From Abnormal Drive"

