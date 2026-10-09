# Title: Potential Persistence Via Microsoft Office Add-In
# ID: 8e1cb247-6cf6-42fa-b440-3f27d57e9936
# Status: test
# Level: high
# Author: NVISO
# Date: 2020-05-11
# Tags: attack.persistence, attack.t1137.006
# Description: Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via Microsoft Office Add-In
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*\\Microsoft\\Addins\\*" AND (TargetFilename="*.xlam" OR TargetFilename="*.xla" OR TargetFilename="*.ppam")) OR (TargetFilename="*\\Microsoft\\Word\\Startup\\*" AND TargetFilename="*.wll") OR (TargetFilename="*Microsoft\\Excel\\XLSTART\\*" AND TargetFilename="*.xlam") OR (TargetFilename="*\\Microsoft\\Excel\\Startup\\*" AND TargetFilename="*.xll"))
    return True

def title(event):
    return "Potential Persistence Via Microsoft Office Add-In"

