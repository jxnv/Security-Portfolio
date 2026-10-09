# Title: Potentially Suspicious File Download From ZIP TLD
# ID: 0bb4bbeb-fe52-4044-b40c-430a04577ebe
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2023-05-18
# Tags: attack.stealth
# Description: Detects the download of a file with a potentially suspicious extension from a .zip top level domain.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious File Download From ZIP TLD
def rule(event):
    # Detection Logic:
    # (Contents="*.zip/*" AND (TargetFilename="*.bat:Zone*" OR TargetFilename="*.dat:Zone*" OR TargetFilename="*.dll:Zone*" OR TargetFilename="*.doc:Zone*" OR TargetFilename="*.docm:Zone*" OR TargetFilename="*.exe:Zone*" OR TargetFilename="*.hta:Zone*" OR TargetFilename="*.pptm:Zone*" OR TargetFilename="*.ps1:Zone*" OR TargetFilename="*.rar:Zone*" OR TargetFilename="*.rtf:Zone*" OR TargetFilename="*.sct:Zone*" OR TargetFilename="*.vbe:Zone*" OR TargetFilename="*.vbs:Zone*" OR TargetFilename="*.ws:Zone*" OR TargetFilename="*.wsf:Zone*" OR TargetFilename="*.xll:Zone*" OR TargetFilename="*.xls:Zone*" OR TargetFilename="*.xlsm:Zone*" OR TargetFilename="*.zip:Zone*"))
    return True

def title(event):
    return "Potentially Suspicious File Download From ZIP TLD"

